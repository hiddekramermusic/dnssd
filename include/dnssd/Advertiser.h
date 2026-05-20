#pragma once

#if _WIN32 && USE_WINDNS
#include "dnssd/windns/WindnsAdvertiser.h"
#elif USE_AVAHI
#include "dnssd/avahi/AvahiAdvertiser.h"
#else
#include "dnssd/bonjour/BonjourAdvertiser.h"
#endif

namespace dnssd
{

#if _WIN32 && USE_WINDNS
using Advertiser = WindnsAdvertiser;
#elif USE_AVAHI
using Advertiser = AvahiAdvertiser;
#else
using Advertiser = BonjourAdvertiser;
#endif

} // namespace dnssd
