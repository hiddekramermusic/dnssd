#pragma once

#include "Avahi.h"
#include "dnssd/common/AdvertiserBase.h"

#include <mutex>
#include <thread>
#include <atomic>

namespace dnssd
{

class AvahiAdvertiser : public AdvertiserBase
{
public:
    AvahiAdvertiser();
    ~AvahiAdvertiser() override;

    Result registerService (
        const std::string& regType,
        const char* name,
        const char* domain,
        uint16_t port,
        const TxtRecord& txtRecord) noexcept override;

    Result updateTxtRecord (const TxtRecord& txtRecord) override;
    void unregisterService() noexcept override;

private:
    AvahiSimplePoll* mSimplePoll = nullptr;
    AvahiClient* mClient = nullptr;
    AvahiEntryGroup* mEntryGroup = nullptr;

    std::string mRegType;
    std::string mName;
    std::string mDomain;
    uint16_t mPort = 0;
    TxtRecord mTxtRecord;

    std::thread mThread;
    std::atomic<bool> mStopThread { false };
    std::mutex mMutex;

    static void clientCallback (AvahiClient* c, AvahiClientState state, void* userdata);
    static void entryGroupCallback (AvahiEntryGroup* g, AvahiEntryGroupState state, void* userdata);

    void createService();
    void threadLoop();
};

} // namespace dnssd
