#include "dnssd/windns/WindnsBrowser.h"
#include "dnssd/windns/WindnsUtil.h"

namespace
{

/**
 * Splits a fully-qualified service instance name into its components.
 *
 * Expects the form "<name>.<type>.<domain>" where <type> has exactly two DNS labels
 * (e.g. "_http._tcp") and <domain> is "local". Works backwards from ".local" so that
 * service names containing "._" are handled correctly.
 *
 * @param instanceName  Instance name as received from DnsServiceBrowse (e.g. "My Device._http._tcp.local").
 * @param name          Receives the service instance name (e.g. "My Device").
 * @param type          Receives the service type with trailing dot (e.g. "_http._tcp.").
 * @param domain        Receives the domain with trailing dot (e.g. "local.").
 * @return true on success, false if the name cannot be parsed.
 */
bool parseInstanceName (
    const std::string& instanceName,
    std::string& name,
    std::string& type,
    std::string& domain)
{
    const std::string localSuffix = ".local";
    const auto localPos = instanceName.rfind (localSuffix);
    if (localPos == std::string::npos || localPos == 0)
    {
        DNSSD_LOG_DEBUG ("instance name does not end in .local: " << instanceName << std::endl);
        return false;
    }

    // Everything before ".local": "<name>._type._proto"
    const std::string nameAndType = instanceName.substr (0, localPos);

    // Find the 2nd dot from the right — that is where the name ends and the type begins.
    // Using rfind twice handles service names that themselves contain "._".
    auto dotPos = nameAndType.rfind ('.');
    if (dotPos == std::string::npos || dotPos == 0)
        return false;
    dotPos = nameAndType.rfind ('.', dotPos - 1);
    if (dotPos == std::string::npos)
        return false;

    name = nameAndType.substr (0, dotPos);
    type = nameAndType.substr (dotPos + 1) + "."; // e.g. "_http._tcp."
    domain = "local.";
    return true;
}

} // namespace

namespace dnssd
{

WindnsBrowser::~WindnsBrowser()
{
    {
        std::lock_guard<std::recursive_mutex> lg (mLock);

        // Cancel resolve and address queries first — these have no guaranteed final callback.
        for (auto& entry : mServices)
        {
            WindnsDiscoveredService& service = entry.second;
            if (service.resolveStarted && !service.resolveFinished)
            {
                DWORD res = DnsServiceResolveCancel (&service.resolveCancel);
                if (res != ERROR_SUCCESS && res != ERROR_CANCELLED)
                    DNSSD_LOG_DEBUG ("WindnsBrowser::~WindnsBrowser: DnsServiceResolveCancel failed: "
                                     << Result (static_cast<DNS_STATUS> (res)).description() << std::endl)
            }
            if (service.aQueryInFlight)
            {
                DWORD res = DnsCancelQuery (&service.aCancel);
                if (res != ERROR_SUCCESS && res != ERROR_CANCELLED)
                    DNSSD_LOG_DEBUG ("WindnsBrowser::~WindnsBrowser: DnsCancelQuery (A) failed: "
                                     << Result (static_cast<DNS_STATUS> (res)).description() << std::endl)
            }
            if (service.aaaaQueryInFlight)
            {
                DWORD res = DnsCancelQuery (&service.aaaaCancel);
                if (res != ERROR_SUCCESS && res != ERROR_CANCELLED)
                    DNSSD_LOG_DEBUG ("WindnsBrowser::~WindnsBrowser: DnsCancelQuery (AAAA) failed: "
                                     << Result (static_cast<DNS_STATUS> (res)).description() << std::endl)
            }
        }
        mServices.clear();

        // Cancel browses last — DnsServiceBrowseCancel guarantees one final browseCallback
        // with ERROR_CANCELLED, which we use as a synchronisation point below.
        mPendingBrowseCancels = static_cast<int> (mBrowseCancels.size());
        for (auto& entry : mBrowseCancels)
        {
            DWORD res = DnsServiceBrowseCancel (&entry.second);
            if (res != ERROR_SUCCESS && res != ERROR_CANCELLED)
                DNSSD_LOG_DEBUG ("WindnsBrowser::~WindnsBrowser: DnsServiceBrowseCancel failed: "
                                 << Result (static_cast<DNS_STATUS> (res)).description() << std::endl)
        }
        mBrowseCancels.clear();
    }

    std::unique_lock<std::mutex> lk (mCancelMutex);
    bool completed = mCancelCv.wait_for (lk, kWindnsCallbackTimeout, [this]() { return mPendingBrowseCancels == 0; });
    if (!completed)
        DNSSD_LOG_DEBUG ("WindnsBrowser::~WindnsBrowser: timed out waiting for browse cancellation callbacks" << std::endl)
}

Result WindnsBrowser::browseFor (const std::string& serviceType)
{
    std::wstring queryName;
    auto r = toWideString (serviceType, queryName);
    if (r.hasError())
        return r;

    // Normalize to the form "_type._proto.local" expected by DnsServiceBrowse:
    // strip any trailing dots, then append .local if not already present.
    while (!queryName.empty() && queryName.back() == L'.')
        queryName.pop_back();

    if (queryName.rfind (L".local") == std::wstring::npos)
        queryName += L".local";

    std::lock_guard<std::recursive_mutex> lg (mLock);

    if (mBrowseCancels.count (queryName) > 0)
        return Result ("already browsing for service \"" + serviceType + "\"");


    DNS_SERVICE_BROWSE_REQUEST req {};
    req.Version = DNS_QUERY_REQUEST_VERSION1;
    req.InterfaceIndex = 0; // all interfaces
    req.QueryName = queryName.c_str();
    req.pBrowseCallback = &WindnsBrowser::browseCallback;
    req.pQueryContext = this;

    auto& it = mBrowseCancels.emplace (queryName, DNS_SERVICE_CANCEL {}).first;

    DWORD status = DnsServiceBrowse (&req, &it->second);

    if (status != DNS_REQUEST_PENDING && status != ERROR_SUCCESS)
    {
        mBrowseCancels.erase (it);
        return Result (static_cast<DNS_STATUS> (status));
    }

    return {};
}

VOID WINAPI WindnsBrowser::browseCallback (DWORD Status, PVOID pQueryContext, PDNS_RECORD pDnsRecord)
{
    auto* self = static_cast<WindnsBrowser*> (pQueryContext);

    // Cancelling the browse request calls this callback one more time for cleanup.
    if (static_cast<DNS_STATUS> (Status) == ERROR_CANCELLED)
    {
        std::lock_guard<std::mutex> lk (self->mCancelMutex);
        if (--self->mPendingBrowseCancels == 0)
            self->mCancelCv.notify_one();
        return;
    }

    std::lock_guard<std::recursive_mutex> lg (self->mLock);

    DNSSD_LOG_DEBUG ("> browseCallback enter" << std::endl)

    if (self->reportIfError (Result (static_cast<DNS_STATUS> (Status))))
        return;

    for (PDNS_RECORD record = pDnsRecord; record != nullptr; record = record->pNext)
    {
        if (record->wType != DNS_TYPE_PTR)
            continue;

        if (record->Data.PTR.pNameHost == nullptr)
        {
            DNSSD_LOG_DEBUG ("- browseCallback: host name string was nullptr" << std::endl);
            continue;
        }

        std::string instanceName;
        if (toNarrowString (record->Data.PTR.pNameHost, instanceName).hasError())
        {
            DNSSD_LOG_DEBUG ("- browseCallback: failed to convert instance name" << std::endl);
            continue;
        }

        if (record->dwTtl == 0)
        {
            // Goodbye packet — the service is being removed
            auto it = self->mServices.find (instanceName);
            if (it == self->mServices.end())
                continue;

            WindnsDiscoveredService& service = it->second;

            if (service.resolveStarted && !service.resolveFinished)
                DnsServiceResolveCancel (&service.resolveCancel);
            if (service.aQueryInFlight)
                DnsCancelQuery (&service.aCancel);
            if (service.aaaaQueryInFlight)
                DnsCancelQuery (&service.aaaaCancel);

            DNSSD_LOG_DEBUG ("- browseCallback: removed " << service.description.fullname << std::endl)

            if (self->onServiceRemovedCallback)
                self->onServiceRemovedCallback (service.description);

            self->mServices.erase (it);
        }
        else
        {
            auto it = self->mServices.find (instanceName);

            if (it == self->mServices.end())
            {
                // First sighting — parse the instance name and create a new entry
                std::string name, type, domain;
                if (!parseInstanceName (instanceName, name, type, domain))
                {
                    DNSSD_LOG_DEBUG ("- browseCallback: failed to parse instance name, skipping" << std::endl)
                    continue;
                }

                WindnsDiscoveredService service;
                service.ttl = record->dwTtl;
                service.description.fullname = instanceName;
                service.description.name = name;
                service.description.type = type;
                service.description.domain = domain;

                it = self->mServices.emplace (instanceName, std::move (service)).first;

                DNSSD_LOG_DEBUG ("- browseCallback: discovered " << instanceName << std::endl)

                if (self->onServiceDiscoveredCallback)
                    self->onServiceDiscoveredCallback (it->second.description);

                self->issueResolve (instanceName);
            }
            else
            {
                // Subsequent sighting — service is reachable on another interface or address.
                // Do not fire onServiceDiscovered again; refresh addresses if already resolved.
                it->second.ttl = record->dwTtl;

				// If resolve is still in flight it will issue address queries on completion
                if (it->second.resolveFinished && !it->second.description.hostTarget.empty())
                    self->issueAddressQueries (instanceName, it->second.description.hostTarget);
            }
        }
    }

    DNSSD_LOG_DEBUG ("< browseCallback exit" << std::endl)
}

VOID WINAPI WindnsBrowser::resolveCallback (DWORD Status, PVOID pQueryContext, PDNS_SERVICE_INSTANCE pInstance)
{
    auto* ctx = static_cast<ResolveContext*> (pQueryContext);
    auto* self = ctx->owner;
    std::string instanceName = ctx->instanceName;
    delete ctx;

    std::lock_guard<std::recursive_mutex> lg (self->mLock);

    DNSSD_LOG_DEBUG ("> resolveCallback enter: " << instanceName << std::endl)

    auto it = self->mServices.find (instanceName);
    if (it == self->mServices.end())
    {
        DNSSD_LOG_DEBUG ("- resolveCallback: service already removed, discarding result" << std::endl)
        if (pInstance != nullptr)
            DnsServiceFreeInstance (pInstance);
        return;
    }

    it->second.resolveFinished = true;

    if (self->reportIfError (Result (static_cast<DNS_STATUS> (Status))))
    {
        DNSSD_LOG_DEBUG ("- resolveCallback: resolve failed for " << instanceName << std::endl)
        if (pInstance != nullptr)
            DnsServiceFreeInstance (pInstance);
        return;
    }

    if (pInstance == nullptr)
    {
        DNSSD_LOG_DEBUG ("- resolveCallback: pInstance is null"  << std::endl)
        return;
    }

    self->onResolveResult (instanceName, pInstance);
    DnsServiceFreeInstance (pInstance);

    DNSSD_LOG_DEBUG ("< resolveCallback exit: " << instanceName << std::endl)
}

VOID WINAPI WindnsBrowser::aQueryCallback (PVOID pQueryContext, PDNS_QUERY_RESULT pQueryResults)
{
    auto* ctx = static_cast<AddressQueryContext*> (pQueryContext);
    auto* self = ctx->owner;
    const std::string instanceName = ctx->instanceName;

    std::lock_guard<std::recursive_mutex> lg (self->mLock);

    DNSSD_LOG_DEBUG ("> aQueryCallback enter: " << instanceName << std::endl)

    auto it = self->mServices.find (instanceName);
    if (it != self->mServices.end())
        it->second.aQueryInFlight = false;

    if (pQueryResults == nullptr || pQueryResults->QueryStatus != ERROR_SUCCESS)
    {
        if (pQueryResults != nullptr && it != self->mServices.end())
            self->reportIfError (Result (static_cast<DNS_STATUS> (pQueryResults->QueryStatus)));
        delete ctx;
        return;
    }

    if (it == self->mServices.end())
    {
        DNSSD_LOG_DEBUG ("- aQueryCallback: service already removed, discarding" << std::endl)
        DnsRecordListFree (pQueryResults->pQueryRecords, DnsFreeRecordList);
        delete ctx;
        return;
    }

    self->onAddressResult (instanceName, pQueryResults->pQueryRecords);
    DnsRecordListFree (pQueryResults->pQueryRecords, DnsFreeRecordList);

    DNSSD_LOG_DEBUG ("< aQueryCallback exit: " << instanceName << std::endl)
    delete ctx;
}

VOID WINAPI WindnsBrowser::aaaaQueryCallback (PVOID pQueryContext, PDNS_QUERY_RESULT pQueryResults)
{
    auto* ctx = static_cast<AddressQueryContext*> (pQueryContext);
    auto* self = ctx->owner;
    const std::string instanceName = ctx->instanceName;

    std::lock_guard<std::recursive_mutex> lg (self->mLock);

    DNSSD_LOG_DEBUG ("> aaaaQueryCallback enter: " << instanceName << std::endl)

    auto it = self->mServices.find (instanceName);
    if (it != self->mServices.end())
        it->second.aaaaQueryInFlight = false;

    if (pQueryResults == nullptr || pQueryResults->QueryStatus != ERROR_SUCCESS)
    {
        if (pQueryResults != nullptr && it != self->mServices.end())
            self->reportIfError (Result (static_cast<DNS_STATUS> (pQueryResults->QueryStatus)));
        delete ctx;
        return;
    }

    if (it == self->mServices.end())
    {
        DNSSD_LOG_DEBUG ("- aaaaQueryCallback: service already removed, discarding" << std::endl)
        DnsRecordListFree (pQueryResults->pQueryRecords, DnsFreeRecordList);
        delete ctx;
        return;
    }

    self->onAddressResult (instanceName, pQueryResults->pQueryRecords);
    DnsRecordListFree (pQueryResults->pQueryRecords, DnsFreeRecordList);

    DNSSD_LOG_DEBUG ("< aaaaQueryCallback exit: " << instanceName << std::endl)
    delete ctx;
}

void WindnsBrowser::issueResolve (const std::string& instanceName)
{
    auto it = mServices.find (instanceName);
    if (it == mServices.end())
        return;

    std::wstring instanceNameW;
    auto r = toWideString (instanceName, instanceNameW);
    if (reportIfError (r))
        return;

    auto* ctx = new ResolveContext { this, instanceName };

    DNS_SERVICE_RESOLVE_REQUEST req {};
    req.Version = DNS_QUERY_REQUEST_VERSION1;
    req.InterfaceIndex = 0;
    req.QueryName = const_cast<PWSTR> (instanceNameW.c_str());
    req.pResolveCompletionCallback = &WindnsBrowser::resolveCallback;
    req.pQueryContext = ctx;

    DWORD status = DnsServiceResolve (&req, &it->second.resolveCancel);

    if (status != DNS_REQUEST_PENDING && status != ERROR_SUCCESS)
    {
        delete ctx;
        reportIfError (Result (static_cast<DNS_STATUS> (status)));
        return;
    }

    it->second.resolveStarted = true;
}

void WindnsBrowser::issueAddressQueries (const std::string& instanceName, const std::string& hostName)
{
    auto it = mServices.find (instanceName);
    if (it == mServices.end())
        return;

    WindnsDiscoveredService& service = it->second;

    if (service.aQueryInFlight)
    {
        DWORD res = DnsCancelQuery (&service.aCancel);
        if (res != ERROR_SUCCESS && res != ERROR_CANCELLED)
            DNSSD_LOG_DEBUG ("WindnsBrowser::issueAddressQueries: DnsCancelQuery (A) failed: "
                             << Result (static_cast<DNS_STATUS> (res)).description() << std::endl)
        service.aQueryInFlight = false;
    }
    if (service.aaaaQueryInFlight)
    {
        DWORD res = DnsCancelQuery (&service.aaaaCancel);
        if (res != ERROR_SUCCESS && res != ERROR_CANCELLED)
            DNSSD_LOG_DEBUG ("WindnsBrowser::issueAddressQueries: DnsCancelQuery (AAAA) failed: "
                             << Result (static_cast<DNS_STATUS> (res)).description() << std::endl)
        service.aaaaQueryInFlight = false;
    }

    std::wstring hostNameW;
    auto r = toWideString (hostName, hostNameW);
    if (reportIfError (r))
        return;

    // A record (IPv4) query
    {
        auto* ctx = new AddressQueryContext { this, instanceName };
        ctx->queryResult.Version = DNS_QUERY_REQUEST_VERSION1;

        DNS_QUERY_REQUEST req {};
        req.Version = DNS_QUERY_REQUEST_VERSION1;
        req.QueryName = hostNameW.c_str();
        req.QueryType = DNS_TYPE_A;
        req.QueryOptions = DNS_QUERY_STANDARD;
        req.InterfaceIndex = 0;
        req.pQueryCompletionCallback = &WindnsBrowser::aQueryCallback;
        req.pQueryContext = ctx;

        DWORD status = DnsQueryEx (&req, &ctx->queryResult, &service.aCancel);

        if (status == ERROR_SUCCESS)
        {
            onAddressResult (instanceName, ctx->queryResult.pQueryRecords);
            DnsRecordListFree (ctx->queryResult.pQueryRecords, DnsFreeRecordList);
            delete ctx;
        }
        else if (status == DNS_REQUEST_PENDING)
        {
            service.aQueryInFlight = true;
        }
        else
        {
            delete ctx;
            reportIfError (Result (static_cast<DNS_STATUS> (status)));
        }
    }

    // AAAA record (IPv6) query
    {
        auto* ctx = new AddressQueryContext { this, instanceName };
        ctx->queryResult.Version = DNS_QUERY_REQUEST_VERSION1;

        DNS_QUERY_REQUEST req {};
        req.Version = DNS_QUERY_REQUEST_VERSION1;
        req.QueryName = hostNameW.c_str();
        req.QueryType = DNS_TYPE_AAAA;
        req.QueryOptions = DNS_QUERY_STANDARD;
        req.InterfaceIndex = 0;
        req.pQueryCompletionCallback = &WindnsBrowser::aaaaQueryCallback;
        req.pQueryContext = ctx;

        DWORD status = DnsQueryEx (&req, &ctx->queryResult, &service.aaaaCancel);

        if (status == ERROR_SUCCESS)
        {
            onAddressResult (instanceName, ctx->queryResult.pQueryRecords);
            DnsRecordListFree (ctx->queryResult.pQueryRecords, DnsFreeRecordList);
            delete ctx;
        }
        else if (status == DNS_REQUEST_PENDING)
        {
            service.aaaaQueryInFlight = true;
        }
        else
        {
            delete ctx;
            reportIfError (Result (static_cast<DNS_STATUS> (status)));
        }
    }
}

void WindnsBrowser::onResolveResult (const std::string& instanceName, PDNS_SERVICE_INSTANCE pInstance)
{
    auto it = mServices.find (instanceName);
    if (it == mServices.end())
        return;

    ServiceDescription& desc = it->second.description;

    if (pInstance->pszHostName != nullptr)
    {
        auto r = toNarrowString (pInstance->pszHostName, desc.hostTarget);
        if (reportIfError (r))
            return;
    }

    desc.port = pInstance->wPort;

    desc.txtRecord.clear();
    for (DWORD i = 0; i < pInstance->dwPropertyCount; ++i)
    {
        if (pInstance->keys == nullptr || pInstance->keys[i] == nullptr)
            continue;

        std::string key, value;
        auto rKey = toNarrowString (pInstance->keys[i], key);
        if (rKey.hasError())
        {
            DNSSD_LOG_DEBUG ("- onResolveResult: failed to convert TXT key at index " << i << std::endl)
            continue;
        }

        if (pInstance->values != nullptr && pInstance->values[i] != nullptr)
        {
            auto rVal = toNarrowString (pInstance->values[i], value);
            if (rVal.hasError())
            {
                DNSSD_LOG_DEBUG ("- onResolveResult: failed to convert TXT value for key \"" << key << "\"" << std::endl)
                continue;
            }
        }

        desc.txtRecord[key] = value;
    }

    DNSSD_LOG_DEBUG ("- onResolveResult: " << instanceName << " host=" << desc.hostTarget << " port=" << desc.port << std::endl)

    if (onServiceResolvedCallback)
        onServiceResolvedCallback (desc, pInstance->dwInterfaceIndex);

    if (!desc.hostTarget.empty())
        issueAddressQueries (instanceName, desc.hostTarget);
}

void WindnsBrowser::onAddressResult (const std::string& instanceName, PDNS_RECORD records)
{
    auto it = mServices.find (instanceName);
    if (it == mServices.end())
        return;

    ServiceDescription& desc = it->second.description;
    const uint32_t ifIndex = 0;

    for (PDNS_RECORD record = records; record != nullptr; record = record->pNext)
    {
        std::string address;

        if (record->wType == DNS_TYPE_A)
        {
            char buf[INET_ADDRSTRLEN];
            DWORD ipAddr = record->Data.A.IpAddress;
            if (inet_ntop (AF_INET, &ipAddr, buf, sizeof (buf)) == nullptr)
                continue;
            address = buf;
        }
        else if (record->wType == DNS_TYPE_AAAA)
        {
            char buf[INET6_ADDRSTRLEN];
            if (inet_ntop (AF_INET6, &record->Data.AAAA.Ip6Address, buf, sizeof (buf)) == nullptr)
                continue;
            address = buf;
        }
        else
        {
            continue;
        }

        // Goodbye message for a specific interface
        if (record->dwTtl == 0)
        {
            auto ifIt = desc.interfaces.find (ifIndex);
            if (ifIt != desc.interfaces.end() && ifIt->second.erase (address) > 0)
            {
                if (ifIt->second.empty())
                    desc.interfaces.erase (ifIt);

                DNSSD_LOG_DEBUG ("- onAddressResult: removed " << address << " for " << instanceName << std::endl)

                if (onAddressRemovedCallback)
                    onAddressRemovedCallback (desc, address, ifIndex);
            }
        }
        else
        {
            bool inserted = desc.interfaces[ifIndex].insert (address).second;
            if (inserted)
            {
                DNSSD_LOG_DEBUG ("- onAddressResult: added " << address << " for " << instanceName << std::endl)

                if (onAddressAddedCallback)
                    onAddressAddedCallback (desc, address, ifIndex);
            }
        }
    }
}

bool WindnsBrowser::reportIfError (const Result& result) const noexcept
{
    if (result.hasError())
    {
        if (onBrowseErrorCallback)
            onBrowseErrorCallback (result);
        return true;
    }
    return false;
}

} // namespace dnssd
