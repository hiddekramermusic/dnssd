#include "dnssd/windns/WindnsAdvertiser.h"
#include "dnssd/windns/WindnsUtil.h"

#include <sstream>
#include <string>
#include <vector>
#include <windows.h>
#include <windns.h>

namespace {

/**
 * Builds and registers a DNS-SD service instance on all available network interfaces.
 *
 * @param instanceName - Fully qualified instance name, e.g. L"MyService._http._tcp.local".
 * @param port - The port on which the service is running.
 * @param txtRecord - TXT record key/value pairs.
 * @param ctx - Request context passed to the completion callback.
 * @param req - Register request struct; any existing pServiceInstance is freed and replaced.
 *              Set to nullptr on registration failure.
 * @param cancelHandle - Filled by DnsServiceRegister; pass it to DnsServiceRegisterCancel to cancel the pending
 *                       registration. Must stay alive until the registration completes or is cancelled.
 * @param callback - Completion callback invoked when registration succeeds or fails.
 * @return Empty Result on success, or an error Result if string conversion or registration failed.
 */
dnssd::Result doRegister (
    PCWSTR instanceName,
    uint16_t port,
    const dnssd::TxtRecord& txtRecord,
    dnssd::WindnsAdvertiser::RegisterRequestContext& ctx,
    DNS_SERVICE_REGISTER_REQUEST& req,
    DNS_SERVICE_CANCEL& cancelHandle,
    PDNS_SERVICE_REGISTER_COMPLETE callback)
{
    DWORD bufferSize = 0;
    GetComputerNameExW (ComputerNameDnsHostname, nullptr, &bufferSize);
    if (GetLastError() != ERROR_MORE_DATA)
    {
        std::stringstream msg;
        msg << "Failed to get hostname size. Error code: " << GetLastError();
        return dnssd::Result (msg.str());
    }

    std::wstring hostname;
    hostname.resize (bufferSize);
    if (!GetComputerNameExW (ComputerNameDnsHostname, &hostname[0], &bufferSize))
    {
        std::stringstream msg;
        msg << "Failed to get hostname. Error code: " << GetLastError();
        return dnssd::Result (msg.str());
    }
    hostname.resize (bufferSize); // trim null terminator written by the API
    hostname += L".local";

    // Build TXT record key/value arrays.
    // wstrings must stay alive until DnsServiceConstructInstance returns.
    std::vector<std::wstring> keyStrings, valueStrings;
    keyStrings.reserve (txtRecord.size());
    valueStrings.reserve (txtRecord.size());
    for (const auto& kv : txtRecord)
    {
        std::wstring key, value;
        auto rKey = dnssd::toWideString (kv.first, key);
        if (rKey.hasError()) return rKey;
        auto rValue = dnssd::toWideString (kv.second, value);
        if (rValue.hasError()) return rValue;
        keyStrings.push_back (std::move (key));
        valueStrings.push_back (std::move (value));
    }

    std::vector<PCWSTR> keys, values;
    keys.reserve (keyStrings.size());
    values.reserve (valueStrings.size());
    for (size_t i = 0; i < keyStrings.size(); ++i)
    {
        keys.push_back (keyStrings[i].c_str());
        values.push_back (valueStrings[i].c_str());
    }

    if (req.pServiceInstance != nullptr)
    {
        DnsServiceFreeInstance (req.pServiceInstance);
        req.pServiceInstance = nullptr;
    }

    PDNS_SERVICE_INSTANCE instance = DnsServiceConstructInstance (
        instanceName,
        hostname.c_str(),
        nullptr, // IPv4: let the system determine the address per interface
        nullptr, // IPv6: let the system determine the address per interface
        port,
        0, // priority
        0, // weight
        static_cast<DWORD> (keyStrings.size()),
        keys.data(),
        values.data());

    if (instance == nullptr)
    {
        std::stringstream msg;
        msg << "DnsServiceConstructInstance failed. Error code: " << GetLastError();
        return dnssd::Result (msg.str());
    }

    req = {};
    req.Version = DNS_QUERY_REQUEST_VERSION1;
    req.InterfaceIndex = 0; // Register on all available network interfaces
    req.pServiceInstance = instance;
    req.pRegisterCompletionCallback = callback;
    req.pQueryContext = &ctx;
    req.hCredentials = nullptr;
    req.unicastEnabled = FALSE;

    cancelHandle = {};
    DWORD status = DnsServiceRegister (&req, &cancelHandle);
    if (status != DNS_REQUEST_PENDING && status != ERROR_SUCCESS)
    {
        DnsServiceFreeInstance (instance);
        req.pServiceInstance = nullptr;
        return dnssd::Result (static_cast<DNS_STATUS> (status));
    }

    return {};
}

} // namespace

namespace dnssd
{

Result WindnsAdvertiser::registerService (
    const std::string& regType,
    const char* name,
    const char* domain,
    uint16_t port,
    const TxtRecord& txtRecord) noexcept
{
    if (domain != nullptr)
        return Result ("Windns does not support other domain names than '.local', you need to leave the domain parameter as a nullptr");

    if (mRegistered.load (std::memory_order_acquire) || isRegistrationPending())
        return Result ("Service already registered, unregister first or use updateTxtRecord function to update an existing service");

    mTxtRecord = txtRecord;

    // Build the fully qualified instance name: "<name>.<regType>.local"
    // If no name is given, fall back to the computer's DNS hostname as the service name.
    std::wstring instanceName;
    if (name != nullptr && name[0] != '\0')
    {
        auto r = dnssd::toWideString (name, instanceName);
        if (r.hasError()) return r;
    }
    else
    {
        DWORD bufferSize = 0;
        GetComputerNameExW (ComputerNameDnsHostname, nullptr, &bufferSize);
        if (GetLastError() != ERROR_MORE_DATA)
        {
            std::stringstream msg;
            msg << "Failed to get hostname size. Error code: " << GetLastError();
            return Result (msg.str());
        }
        instanceName.resize (bufferSize);
        if (!GetComputerNameExW (ComputerNameDnsHostname, &instanceName[0], &bufferSize))
        {
            std::stringstream msg;
            msg << "Failed to get hostname. Error code: " << GetLastError();
            return Result (msg.str());
        }
        instanceName.resize (bufferSize);
    }

    std::wstring regTypeW;
    auto r = dnssd::toWideString (regType, regTypeW);
    if (r.hasError()) return r;
    instanceName += L"." + regTypeW + L".local.";

    {
        std::lock_guard<std::mutex> lockGuard (mLock);
        mCtx = { RegisterEventType::Register, this };
        mCallbackPending = true;
    }

    Result result = doRegister (
        instanceName.c_str(),
        port,
        txtRecord,
        mCtx,
        mReq,
        mRegisterCancel,
        registerCompleteCallback);

    if (result.hasError())
    {
        std::lock_guard<std::mutex> lockGuard (mLock);
        mCallbackPending = false;
    }

    return result;
}

Result WindnsAdvertiser::updateTxtRecord (const TxtRecord& txtRecord)
{
    mTxtRecord = txtRecord;

    if (!mRegistered.load (std::memory_order_acquire) && !isRegistrationPending())
        return {};

    if (mReq.pServiceInstance == nullptr)
        return Result ("Failed to update TXT record: no service instance");

    // WinDNS has no in-place TXT update API; deregister (or cancel the pending registration) and re-register.
    // Copy the existing instance name and port before doRegister frees the instance.
    std::wstring instanceName (mReq.pServiceInstance->pszInstanceName);
    uint16_t port = mReq.pServiceInstance->wPort;

    unregisterService();

    if (mRegistered.load (std::memory_order_acquire) || isRegistrationPending())
        return Result ("Failed to update TXT record: the existing service could not be unregistered");

    {
        std::lock_guard<std::mutex> lockGuard (mLock);
        mCtx = { RegisterEventType::Register, this };
        mCallbackPending = true;
    }

    Result result = doRegister (instanceName.c_str(), port, txtRecord, mCtx, mReq, mRegisterCancel, registerCompleteCallback);

    if (result.hasError())
    {
        std::lock_guard<std::mutex> lockGuard (mLock);
        mCallbackPending = false;
    }

    return result;
}

void WindnsAdvertiser::unregisterService() noexcept
{
    if (isRegistrationPending())
        cancelPendingRegistration();

    if (!mRegistered.load (std::memory_order_acquire))
        return;

    {
        std::lock_guard<std::mutex> lockGuard (mLock);
        mCtx.event_type = RegisterEventType::Deregister;
        mCallbackPending = true;
    }

    DWORD status = DnsServiceDeRegister (&mReq, nullptr); // pCancel must be nullptr

    if (status != DNS_REQUEST_PENDING)
    {
        {
            std::lock_guard<std::mutex> lockGuard (mLock);
            mCallbackPending = false;
        }

        std::stringstream message;
        message << "Deregistering DNS Service failed: " << Result (static_cast<DNS_STATUS> (status)).description();
        DNSSD_LOG_DEBUG (message.str() << std::endl)

        if (onAdvertiserErrorCallback)
            onAdvertiserErrorCallback (Result (message.str()));
        return;
    }

    std::unique_lock<std::mutex> lock (mLock);
    bool completed = mCv.wait_for (lock, kWindnsCallbackTimeout, [this]() { return !mCallbackPending; });
    if (!completed)
        DNSSD_LOG_DEBUG ("WindnsAdvertiser::unregisterService: timed out waiting for deregister callback" << std::endl)
}

bool WindnsAdvertiser::isRegistrationPending()
{
    std::lock_guard<std::mutex> lockGuard (mLock);
    return mCallbackPending && mCtx.event_type == RegisterEventType::Register;
}

void WindnsAdvertiser::cancelPendingRegistration() noexcept
{
    DWORD res = DnsServiceRegisterCancel (&mRegisterCancel);

    if (res == ERROR_SUCCESS || res == ERROR_CANCELLED)
    {
        // Cancelled synchronously. registerCompleteCallback ignores ERROR_CANCELLED, so don't wait for it.
        std::lock_guard<std::mutex> lockGuard (mLock);
        mCallbackPending = false;
        return;
    }

    DNSSD_LOG_DEBUG ("WindnsAdvertiser::cancelPendingRegistration: DnsServiceRegisterCancel failed: ("
                     << res << ") " << Result (static_cast<DNS_STATUS> (res)).description() << std::endl)

    // The registration was not cancelled, so its callback can still arrive. Wait for it, so that the caller
    // can see whether the service ended up registered and deregister it.
    std::unique_lock<std::mutex> lock (mLock);
    bool completed = mCv.wait_for (lock, kWindnsCallbackTimeout, [this]() { return !mCallbackPending; });
    if (!completed)
        DNSSD_LOG_DEBUG ("WindnsAdvertiser::cancelPendingRegistration: timed out waiting for register callback" << std::endl)
}

WindnsAdvertiser::~WindnsAdvertiser()
{
    // Cancels a pending registration, or deregisters and waits for the deregister callback.
    unregisterService();

    if (mReq.pServiceInstance != nullptr)
    {
        DnsServiceFreeInstance (mReq.pServiceInstance);
        mReq.pServiceInstance = nullptr;
    }
}

VOID WINAPI WindnsAdvertiser::registerCompleteCallback (DWORD Status, PVOID pQueryContext, PDNS_SERVICE_INSTANCE pInstance)
{
    // A registration cancelled with DnsServiceRegisterCancel is not waited on. If WinDNS still calls back for it,
    // the context may already belong to a newer request or to a destroyed advertiser, so don't touch it.
    if (Status == ERROR_CANCELLED)
        return;

    auto* ctx = static_cast<dnssd::WindnsAdvertiser::RegisterRequestContext*> (pQueryContext);

    if (ctx == nullptr)
        return;

    DNSSD_LOG_DEBUG ("> registerCompleteCallback enter" << std::endl);

    if (ctx->event_type == dnssd::WindnsAdvertiser::RegisterEventType::Register)
    {
        DNSSD_LOG_DEBUG ("- registerCompleteCallback event type register" << std::endl);
        if (Status == ERROR_SUCCESS)
        {
            if (auto* owner = static_cast<dnssd::WindnsAdvertiser*> (ctx->owner))
                owner->mRegistered.store (true, std::memory_order_release);
        }
        else
        {
            dnssd::Result res (Status);
            std::stringstream expanded_message;
            expanded_message << "Registering DNS Service failed: " << res.description();
            res = dnssd::Result (expanded_message.str());

            DNSSD_LOG_DEBUG (expanded_message.str());

            if (auto* owner = static_cast<dnssd::WindnsAdvertiser*> (ctx->owner))
                if (owner->onAdvertiserErrorCallback)
                    owner->onAdvertiserErrorCallback (res);
        }
    }

    if (ctx->event_type == dnssd::WindnsAdvertiser::RegisterEventType::Deregister)
    {
        DNSSD_LOG_DEBUG ("- registerCompleteCallback event type deregister" << std::endl);
        if (Status == ERROR_SUCCESS)
        {
            if (auto* owner = static_cast<dnssd::WindnsAdvertiser*> (ctx->owner))
                owner->mRegistered.store (false, std::memory_order_release);
        }
        else
        {
            dnssd::Result res (Status);
            std::stringstream expanded_message;
            expanded_message << "Deregistering DNS Service failed: " << res.description();
            res = dnssd::Result (expanded_message.str());

            DNSSD_LOG_DEBUG (expanded_message.str());

            if (auto* owner = static_cast<dnssd::WindnsAdvertiser*> (ctx->owner))
                if (owner->onAdvertiserErrorCallback)
                    owner->onAdvertiserErrorCallback (res);
        }
    }

    if (auto* owner = static_cast<dnssd::WindnsAdvertiser*> (ctx->owner))
        owner->onCallbackFinished();

    DNSSD_LOG_DEBUG ("< registerCompleteCallback exit" << std::endl);
}

void WindnsAdvertiser::onCallbackFinished()
{
    std::lock_guard<std::mutex> lockGuard (mLock);
    mCallbackPending = false;
    mCv.notify_one();
}

} // namespace dnssd
