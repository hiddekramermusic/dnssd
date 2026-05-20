#pragma once

#include "Avahi.h"
#include "dnssd/common/BrowserBase.h"

#include <map>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>

namespace dnssd
{

class AvahiBrowser : public BrowserBase
{
public:
    AvahiBrowser();
    ~AvahiBrowser() override;

    Result browseFor (const std::string& serviceType) override;

private:
    AvahiSimplePoll* mSimplePoll = nullptr;
    AvahiClient* mClient = nullptr;
    
    struct BrowserContext {
        AvahiBrowser* owner;
        std::string serviceType;
    };

    struct ServiceInstance {
        std::string name;
        std::string type;
        std::string domain;
        AvahiIfIndex interface;
        AvahiProtocol protocol;
        AvahiServiceResolver* resolver = nullptr;
        ServiceDescription description;

        bool operator<(const ServiceInstance& other) const {
            if (name != other.name) return name < other.name;
            if (type != other.type) return type < other.type;
            if (domain != other.domain) return domain < other.domain;
            if (interface != other.interface) return interface < other.interface;
            return protocol < other.protocol;
        }
    };

    std::map<std::string, AvahiServiceBrowser*> mBrowsers;
    std::vector<BrowserContext*> mContexts;
    std::map<ServiceInstance, ServiceInstance> mInstances;

    std::thread mThread;
    std::atomic<bool> mStopThread { false };
    std::mutex mMutex;

    static void clientCallback (AvahiClient* c, AvahiClientState state, void* userdata);
    static void browseCallback (
        AvahiServiceBrowser* b,
        AvahiIfIndex interface,
        AvahiProtocol protocol,
        AvahiBrowserEvent event,
        const char* name,
        const char* type,
        const char* domain,
        AvahiLookupResultFlags flags,
        void* userdata);

    static void resolveCallback (
        AvahiServiceResolver* r,
        AvahiIfIndex interface,
        AvahiProtocol protocol,
        AvahiResolverEvent event,
        const char* name,
        const char* type,
        const char* domain,
        const char* host_name,
        const AvahiAddress* a,
        uint16_t port,
        AvahiStringList* txt,
        AvahiLookupResultFlags flags,
        void* userdata);

    void threadLoop();
};

} // namespace dnssd
