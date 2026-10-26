#pragma once

#if !_WIN32 || !USE_WINDNS
#error This file should only be included on Windows builds and have the 'USE_WINDNS' compilation flag enabled.
#endif

#include "Windns.h"
#include "dnssd/common/AdvertiserBase.h"
#include "dnssd/common/Result.h"
#include "dnssd/common/Log.h"
#include <atomic>
#include <mutex>
#include <condition_variable>

namespace dnssd
{

class WindnsAdvertiser : public AdvertiserBase
{
public:
    explicit WindnsAdvertiser() = default;
    ~WindnsAdvertiser();

    // MARK: IAdvertiser implementations -
    Result registerService (
        const std::string& regType,
        const char* name,
        const char* domain,
        uint16_t port,
        const TxtRecord& txtRecord) noexcept override;

    Result updateTxtRecord (const TxtRecord& txtRecord) override;
    void unregisterService() noexcept override;

    enum class RegisterEventType
    {
        Register = 0,
        Deregister
    };

    struct RegisterRequestContext
    {
        RegisterEventType event_type;
        WindnsAdvertiser* owner;
    };

private:
    DNS_SERVICE_REGISTER_REQUEST mReq { 0 };
    RegisterRequestContext mCtx {};
    DNS_SERVICE_CANCEL mRegisterCancel {}; // Filled by DnsServiceRegister, used by DnsServiceRegisterCancel
    TxtRecord mTxtRecord;

    bool mCallbackPending = false; // Guarded by mLock. True while a register or deregister callback is outstanding.
    std::atomic<bool> mRegistered { false };

    std::mutex mLock; // For synchronisation with the callback
    std::condition_variable mCv; // For synchronisation with the callback

	static VOID WINAPI registerCompleteCallback (DWORD Status, PVOID pQueryContext, PDNS_SERVICE_INSTANCE pInstance);

    /**
    * Used by registerCompleteCallback to synchronise with unregisterService.
    */
    void onCallbackFinished();

    /**
    * @return true if a DnsServiceRegister call is waiting for its completion callback.
    */
    bool isRegistrationPending();

    /**
    * Cancels a pending registration with DnsServiceRegisterCancel. Returns without waiting if the cancel succeeds.
    * If the cancel fails, the registration may already be completing, so it waits (up to kWindnsCallbackTimeout)
    * for the register callback.
    */
    void cancelPendingRegistration() noexcept;
};

} // namespace dnssd