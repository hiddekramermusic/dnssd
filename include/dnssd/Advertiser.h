#pragma once

#if _WIN32 && USE_WINDNS
#include "dnssd/windns/WindnsAdvertiser.h"
#else
#include "dnssd/bonjour/BonjourAdvertiser.h"
#endif

namespace dnssd
{

#if _WIN32 && USE_WINDNS
using Advertiser = WindnsAdvertiser;
#else
using Advertiser = BonjourAdvertiser;
#endif

} // namespace dnssd
