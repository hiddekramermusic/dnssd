#pragma once

#if !_WIN32 || !USE_WINDNS
#error This file should only be included on Windows builds and have the 'USE_WINDNS' compilation flag enabled.
#endif

#include "Windns.h"
#include "dnssd/common/AdvertiserBase.h"
#include "dnssd/common/Result.h"
#include "dnssd/common/Log.h"
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
    PDNS_SERVICE_CANCEL mCancelPtr = nullptr;
    TxtRecord mTxtRecord;

    bool mCallbackPending = false;
    bool mCallbackFinished = false;
    std::atomic<bool> mRegistered = false;

    std::mutex mLock; // For synchronisation with the callback
    std::condition_variable mCv; // For synchronisation with the callback

	static VOID WINAPI registerCompleteCallback (DWORD Status, PVOID pQueryContext, PDNS_SERVICE_INSTANCE pInstance);

    /**
    * Used by registerCompleteCallback to synchronise with the destructor.
    */
    void onCallbackFinished();
};

} // namespace dnssd