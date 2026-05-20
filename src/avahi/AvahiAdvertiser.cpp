#include "dnssd/avahi/AvahiAdvertiser.h"
#include "dnssd/common/Log.h"

#include <iostream>

namespace dnssd
{

AvahiAdvertiser::AvahiAdvertiser()
{
    mSimplePoll = avahi_simple_poll_new();
    if (!mSimplePoll)
    {
        DNSSD_LOG_DEBUG ("Failed to create Avahi simple poll object.");
        return;
    }

    int error;
    mClient = avahi_client_new (avahi_simple_poll_get (mSimplePoll), static_cast<AvahiClientFlags> (0), clientCallback, this, &error);

    if (!mClient)
    {
        DNSSD_LOG_DEBUG ("Failed to create Avahi client: " << avahi_strerror (error));
        return;
    }

    mThread = std::thread (&AvahiAdvertiser::threadLoop, this);
}

AvahiAdvertiser::~AvahiAdvertiser()
{
    mStopThread = true;
    if (mSimplePoll)
    {
        avahi_simple_poll_quit (mSimplePoll);
    }

    if (mThread.joinable())
    {
        mThread.join();
    }

    std::lock_guard<std::mutex> lock (mMutex);
    if (mEntryGroup)
    {
        avahi_entry_group_free (mEntryGroup);
    }

    if (mClient)
    {
        avahi_client_free (mClient);
    }

    if (mSimplePoll)
    {
        avahi_simple_poll_free (mSimplePoll);
    }
}

Result AvahiAdvertiser::registerService (
    const std::string& regType,
    const char* name,
    const char* domain,
    uint16_t port,
    const TxtRecord& txtRecord) noexcept
{
    std::lock_guard<std::mutex> lock (mMutex);
    mRegType = regType;
    mName = name ? name : "";
    mDomain = domain ? domain : "";
    mPort = port;
    mTxtRecord = txtRecord;

    if (avahi_client_get_state (mClient) == AVAHI_CLIENT_S_RUNNING)
    {
        createService();
    }

    return { Result::Code::NoError };
}

Result AvahiAdvertiser::updateTxtRecord (const TxtRecord& txtRecord)
{
    std::lock_guard<std::mutex> lock (mMutex);
    mTxtRecord = txtRecord;

    if (!mEntryGroup)
    {
        return { Result::Code::UnknownError, "No service registered" };
    }

    AvahiStringList* txtList = txtRecordToAvahiStringList (mTxtRecord);
    int error = avahi_entry_group_update_service_txt_strlst (
        mEntryGroup,
        AVAHI_IF_UNSPEC,
        AVAHI_PROTO_UNSPEC,
        static_cast<AvahiPublishFlags> (0),
        mName.empty() ? nullptr : mName.c_str(),
        mRegType.c_str(),
        mDomain.empty() ? nullptr : mDomain.c_str(),
        txtList);

    avahi_string_list_free (txtList);

    if (error < 0)
    {
        return avahiErrorToResult (error);
    }

    error = avahi_entry_group_commit (mEntryGroup);
    return avahiErrorToResult (error);
}

void AvahiAdvertiser::unregisterService() noexcept
{
    std::lock_guard<std::mutex> lock (mMutex);
    if (mEntryGroup)
    {
        avahi_entry_group_reset (mEntryGroup);
    }
}

void AvahiAdvertiser::clientCallback (AvahiClient* c, AvahiClientState state, void* userdata)
{
    auto* self = static_cast<AvahiAdvertiser*> (userdata);

    switch (state)
    {
        case AVAHI_CLIENT_S_RUNNING:
            self->createService();
            break;

        case AVAHI_CLIENT_S_COLLISION:
        case AVAHI_CLIENT_S_REGISTERING:
            if (self->mEntryGroup)
            {
                avahi_entry_group_reset (self->mEntryGroup);
            }
            break;

        case AVAHI_CLIENT_FAILURE:
            if (self->onAdvertiserErrorCallback)
            {
                self->onAdvertiserErrorCallback (avahiErrorToResult (avahi_client_errno (c)));
            }
            break;

        default:
            break;
    }
}

void AvahiAdvertiser::entryGroupCallback (AvahiEntryGroup* g, AvahiEntryGroupState state, void* userdata)
{
    auto* self = static_cast<AvahiAdvertiser*> (userdata);

    switch (state)
    {
        case AVAHI_ENTRY_GROUP_ESTABLISHED:
            DNSSD_LOG_DEBUG ("Service established.");
            break;

        case AVAHI_ENTRY_GROUP_COLLISION:
        {
            char* n = avahi_alternative_service_name (self->mName.c_str());
            self->mName = n;
            avahi_free (n);
            self->createService();
            break;
        }

        case AVAHI_ENTRY_GROUP_FAILURE:
            if (self->onAdvertiserErrorCallback)
            {
                self->onAdvertiserErrorCallback (avahiErrorToResult (avahi_client_errno (avahi_entry_group_get_client (g))));
            }
            break;

        default:
            break;
    }
}

void AvahiAdvertiser::createService()
{
    if (mRegType.empty())
    {
        return;
    }

    if (!mEntryGroup)
    {
        mEntryGroup = avahi_entry_group_new (mClient, entryGroupCallback, this);
        if (!mEntryGroup)
        {
            if (onAdvertiserErrorCallback)
            {
                onAdvertiserErrorCallback (avahiErrorToResult (avahi_client_errno (mClient)));
            }
            return;
        }
    }

    if (avahi_entry_group_is_empty (mEntryGroup))
    {
        AvahiStringList* txtList = txtRecordToAvahiStringList (mTxtRecord);

        int error = avahi_entry_group_add_service_strlst (
            mEntryGroup,
            AVAHI_IF_UNSPEC,
            AVAHI_PROTO_UNSPEC,
            static_cast<AvahiPublishFlags> (0),
            mName.empty() ? nullptr : mName.c_str(),
            mRegType.c_str(),
            mDomain.empty() ? nullptr : mDomain.c_str(),
            nullptr,
            mPort,
            txtList);

        avahi_string_list_free (txtList);

        if (error < 0)
        {
            if (onAdvertiserErrorCallback)
            {
                onAdvertiserErrorCallback (avahiErrorToResult (error));
            }
            return;
        }

        error = avahi_entry_group_commit (mEntryGroup);
        if (error < 0)
        {
            if (onAdvertiserErrorCallback)
            {
                onAdvertiserErrorCallback (avahiErrorToResult (error));
            }
        }
    }
}

void AvahiAdvertiser::threadLoop()
{
    while (!mStopThread)
    {
        if (avahi_simple_poll_iterate (mSimplePoll, -1) < 0)
        {
            break;
        }
    }
}

} // namespace dnssd
