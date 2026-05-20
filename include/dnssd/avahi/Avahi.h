#pragma once

#include <avahi-client/client.h>
#include <avahi-client/publish.h>
#include <avahi-client/lookup.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-common/alternative.h>
#include <avahi-common/timeval.h>

#include "dnssd/common/Result.h"
#include "dnssd/common/TxtRecord.h"

namespace dnssd
{

/**
 * Utility to convert TxtRecord to AvahiStringList.
 * The caller is responsible for freeing the returned AvahiStringList with avahi_string_list_free.
 */
inline AvahiStringList* txtRecordToAvahiStringList (const TxtRecord& txtRecord)
{
    AvahiStringList* list = nullptr;
    for (auto const& pair : txtRecord)
    {
        list = avahi_string_list_add_pair (list, pair.first.c_str(), pair.second.c_str());
    }
    return list;
}

/**
 * Utility to convert Avahi error code to dnssd::Result.
 */
inline Result avahiErrorToResult (int error)
{
    return Result (error);
}

} // namespace dnssd
