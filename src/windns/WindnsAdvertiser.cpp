#include "../../include/windns/WindnsAdvertiser.h"
#include <sstream>
#include <string>
#include <windows.h>
#include <windns.h>

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
    {
        return Result ("Windns does not support other domain names than '.local', you need to leave the domain parameter as a nullptr");
    }

    mTxtRecord = txtRecord;

    // Get Host name
    DWORD bufferSize = 0;

    GetComputerNameExW (ComputerNameDnsHostname, nullptr, &bufferSize);

    if (GetLastError() != ERROR_MORE_DATA)
    {
        std::stringstream message;
        message << "Failed to get hostname size. Error code: " << GetLastError();
        Result res (message.str());
        return res;
    }

    std::wstring hostname;    
    hostname.resize (bufferSize);

    if (GetComputerNameExW (ComputerNameDnsHostname, &hostname[0], &bufferSize))
    {
        // bufferSize is updated to the number of characters actually written
        // (excluding the null terminator), so we resize the string to trim the extra null.
        hostname.resize (bufferSize);
    }
    else
    {
        std::stringstream message;
        message << "Failed to get hostname. Error code: " << GetLastError();
        Result res (message.str());
        return res;
    }

    DNS_SERVICE_INSTANCE instance { 0 };

    // Initialise to 0 sets InterfaceIndex to 0, which makes DnsServiceRegister broadcast to all available network interfaces
    DNS_SERVICE_REGISTER_REQUEST req { 0 };
    req.Version = DNS_QUERY_REQUEST_VERSION1;


    return {};
}


WindnsAdvertiser::~WindnsAdvertiser()
{
    if (mCallbackPending)
    {
        if (mCtx.event_type == RegisterEventType::Register)
        {
            // Cancel register
            DWORD res = DnsServiceRegisterCancel (mCancelPtr);
            if (res != ERROR_SUCCESS && res != ERROR_CANCELLED)
            {
                std::string descriptive_error = dnssd::Result (res).description();
                std::stringstream message;
                message << "WindnsAdvertiser::~WindnsAdvertiser() : Cancelling registration of DNS service failed with "
                           "status: ("
                        << res << ") and description: (" << descriptive_error << ")";
                DNSSD_LOG_DEBUG (message.str());
            }
        }
    }
    else if (mRegistered)
    {
        // Deregister service
        mCallbackFinished = false;

        mCallbackPending = true;
        DWORD status = DnsServiceDeRegister (&mReq, mCancelPtr);

        if (status == DNS_REQUEST_PENDING)
        {
            std::unique_lock<std::mutex> lock (mLock);
            mCv.wait (lock, [this]() {
                return mCallbackFinished;
            });
        }
    }

    // No pending registrations or deregistrations will be happening at this point
    if (mReq.pServiceInstance != nullptr)
    {
        DnsServiceFreeInstance (mReq.pServiceInstance);
        mReq.pServiceInstance = nullptr;
    }
}

VOID WINAPI WindnsAdvertiser::registerCompleteCallback (DWORD Status, PVOID pQueryContext, PDNS_SERVICE_INSTANCE pInstance)
{
    auto* ctx = static_cast<dnssd::WindnsAdvertiser::RegisterRequestContext*> (pQueryContext);

    if (ctx == nullptr)
    {
        return;
    }

    // Register event
    if (ctx->event_type == dnssd::WindnsAdvertiser::RegisterEventType::Register)
    {
        if (Status == ERROR_SUCCESS)
        {
            if (auto* owner = static_cast<dnssd::WindnsAdvertiser*> (ctx->owner))
            {
                owner->mRegistered = true;
            }
        }
        else
        {
            dnssd::Result res (Status); // Parses status into descriptive message
            std::stringstream expanded_message;
            expanded_message << "Registering DNS Service failed: " << res.description();
            res = dnssd::Result (expanded_message.str());

            if (auto* owner = static_cast<dnssd::WindnsAdvertiser*> (ctx->owner))
            {
                if (owner->onAdvertiserErrorCallback)
                    owner->onAdvertiserErrorCallback (res);
            }
        }
    }

    // Deregister event
    if (ctx->event_type == dnssd::WindnsAdvertiser::RegisterEventType::Deregister)
    {
        if (Status == ERROR_SUCCESS)
        {
            if (auto* owner = static_cast<dnssd::WindnsAdvertiser*> (ctx->owner))
            {
                owner->mRegistered = false;
            }
        }
        else
        {
            dnssd::Result res (Status); // Parses status into descriptive message
            std::stringstream expanded_message;
            expanded_message << "Deregistering DNS Service failed: " << res.description();
            res = dnssd::Result (expanded_message.str());

            if (auto* owner = static_cast<dnssd::WindnsAdvertiser*> (ctx->owner))
            {
                if (owner->onAdvertiserErrorCallback)
                    owner->onAdvertiserErrorCallback (res);
            }
        }
    }

	if (auto* owner = static_cast<dnssd::WindnsAdvertiser*> (ctx->owner))
    {
        owner->onCallbackFinished();
    }
}

void WindnsAdvertiser::onCallbackFinished()
{
    std::lock_guard<std::mutex> lockGaurd (mLock);
    mCallbackFinished = true;
    mCallbackPending = false;
    mCv.notify_one();
}
} // namespace dnssd