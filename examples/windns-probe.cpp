// Temporary WinDNS behaviour probe for the stale-service investigation.
// Not part of the library. Remove this file and its CMake target when the investigation is done.
//
// Commands (run without arguments for usage):
//   browse     - raw DnsServiceBrowse: every callback and record with TTL and timestamp; PTR cache contents first.
//   liveness   - per round: DnsServiceResolve, then SRV queries from cache / mDNS / mDNS bypassing the cache.
//   query      - a single DnsQueryEx for any name and type in one of the three modes.
//   reg-cancel - raw DnsServiceRegister / DnsServiceRegisterCancel / DnsServiceDeRegister sequences.
//   adv        - dnssd::Advertiser (WindnsAdvertiser): register, then immediately unregister / destroy / update TXT.

#include <dnssd/Advertiser.h>
#include <dnssd/windns/Windns.h>
#include <dnssd/windns/WindnsUtil.h>

#include <chrono>
#include <condition_variable>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace
{

using Clock = std::chrono::steady_clock;
const Clock::time_point gStart = Clock::now();
std::mutex gLogMutex;

long long elapsedMs (Clock::time_point since = gStart)
{
    return std::chrono::duration_cast<std::chrono::milliseconds> (Clock::now() - since).count();
}

void logLine (const std::string& line)
{
    std::lock_guard<std::mutex> lg (gLogMutex);
    std::cout << "[" << std::setw (8) << elapsedMs() << " ms tid " << std::setw (5) << GetCurrentThreadId() << "] "
              << line << std::endl;
}

void waitForEnter (const std::string& prompt)
{
    logLine ("PAUSE: " + prompt + " Press enter to continue...");
    std::string line;
    std::getline (std::cin, line);
}

std::string statusText (DWORD status)
{
    std::stringstream s;
    s << status;
    if (status == ERROR_SUCCESS)
        s << " (ERROR_SUCCESS)";
    else if (status == DNS_REQUEST_PENDING)
        s << " (DNS_REQUEST_PENDING)";
    else if (status == ERROR_CANCELLED)
        s << " (ERROR_CANCELLED)";
    else
        s << " (" << dnssd::Result (static_cast<DNS_STATUS> (status)).description() << ")";
    return s.str();
}

std::string narrow (PCWSTR wide)
{
    if (wide == nullptr)
        return "(null)";
    std::string out;
    if (dnssd::toNarrowString (wide, out).hasError())
        return "(conversion failed)";
    return out;
}

std::wstring wide (const std::string& str)
{
    std::wstring out;
    dnssd::toWideString (str, out);
    return out;
}

/// Same normalisation as WindnsBrowser::browseFor: strip trailing dots, append ".local" if missing.
std::wstring serviceTypeQueryName (const std::string& serviceType)
{
    std::wstring name = wide (serviceType);
    while (!name.empty() && name.back() == L'.')
        name.pop_back();
    if (name.rfind (L".local") == std::wstring::npos)
        name += L".local";
    return name;
}

std::string typeName (WORD type)
{
    switch (type)
    {
        case DNS_TYPE_PTR: return "PTR";
        case DNS_TYPE_SRV: return "SRV";
        case DNS_TYPE_TEXT: return "TXT";
        case DNS_TYPE_A: return "A";
        case DNS_TYPE_AAAA: return "AAAA";
        default:
        {
            std::stringstream s;
            s << "type" << type;
            return s.str();
        }
    }
}

std::string recordText (const DNS_RECORD* r)
{
    std::stringstream s;
    s << typeName (r->wType) << " name=" << narrow (r->pName) << " ttl=" << r->dwTtl
      << " section=" << r->Flags.S.Section;

    switch (r->wType)
    {
        case DNS_TYPE_PTR:
            s << " -> " << narrow (r->Data.PTR.pNameHost);
            break;
        case DNS_TYPE_SRV:
            s << " target=" << narrow (r->Data.SRV.pNameTarget) << " port=" << r->Data.SRV.wPort;
            break;
        case DNS_TYPE_TEXT:
            s << " strings=" << r->Data.TXT.dwStringCount;
            for (DWORD i = 0; i < r->Data.TXT.dwStringCount; ++i)
                s << " \"" << narrow (r->Data.TXT.pStringArray[i]) << "\"";
            break;
        case DNS_TYPE_A:
        {
            char buf[INET_ADDRSTRLEN] = {};
            DWORD ip = r->Data.A.IpAddress;
            inet_ntop (AF_INET, &ip, buf, sizeof (buf));
            s << " " << buf;
            break;
        }
        case DNS_TYPE_AAAA:
        {
            char buf[INET6_ADDRSTRLEN] = {};
            inet_ntop (AF_INET6, &r->Data.AAAA.Ip6Address, buf, sizeof (buf));
            s << " " << buf;
            break;
        }
        default:
            break;
    }
    return s.str();
}

void logRecords (const DNS_RECORD* records)
{
    if (records == nullptr)
    {
        logLine ("  (no records)");
        return;
    }
    for (const DNS_RECORD* r = records; r != nullptr; r = r->pNext)
        logLine ("  " + recordText (r));
}

std::string instanceText (const DNS_SERVICE_INSTANCE* inst)
{
    if (inst == nullptr)
        return "(null instance)";

    std::stringstream s;
    s << "instance=" << narrow (inst->pszInstanceName) << " host=" << narrow (inst->pszHostName)
      << " port=" << inst->wPort << " if=" << inst->dwInterfaceIndex << " txt=[";
    for (DWORD i = 0; i < inst->dwPropertyCount; ++i)
    {
        if (i > 0)
            s << ", ";
        s << narrow (inst->keys != nullptr ? inst->keys[i] : nullptr) << "="
          << narrow (inst->values != nullptr ? inst->values[i] : nullptr);
    }
    s << "]";

    if (inst->ip4Address != nullptr)
    {
        char buf[INET_ADDRSTRLEN] = {};
        inet_ntop (AF_INET, inst->ip4Address, buf, sizeof (buf));
        s << " ip4=" << buf;
    }
    else
        s << " ip4=(none)";

    if (inst->ip6Address != nullptr)
    {
        char buf[INET6_ADDRSTRLEN] = {};
        inet_ntop (AF_INET6, inst->ip6Address, buf, sizeof (buf));
        s << " ip6=" << buf;
    }
    else
        s << " ip6=(none)";

    return s.str();
}

// MARK: - Browse

struct BrowseState
{
    std::mutex m;
    std::condition_variable cv;
    bool cancelled = false;
    int callbacks = 0;
};

VOID WINAPI browseCallback (DWORD status, PVOID context, PDNS_RECORD records)
{
    auto* st = static_cast<BrowseState*> (context);
    int n;
    {
        std::lock_guard<std::mutex> lg (st->m);
        n = ++st->callbacks;
    }

    std::stringstream s;
    s << "browseCallback #" << n << " status=" << statusText (status);
    logLine (s.str());
    logRecords (records);

    if (status == ERROR_CANCELLED)
    {
        std::lock_guard<std::mutex> lg (st->m);
        st->cancelled = true;
        st->cv.notify_all();
    }
}

// MARK: - DnsQueryEx

struct QueryState
{
    std::mutex m;
    std::condition_variable cv;
    bool done = false;
    bool abandoned = false; // set when we stopped waiting; the callback then only logs
    std::string label;
    Clock::time_point started;
    DNS_QUERY_RESULT result {};
    DNS_QUERY_CANCEL cancel {};
};

VOID WINAPI queryCallback (PVOID context, PDNS_QUERY_RESULT results)
{
    auto* q = static_cast<QueryState*> (context);
    std::lock_guard<std::mutex> lg (q->m);
    if (q->abandoned)
    {
        std::stringstream s;
        s << "LATE query callback " << q->label << " after " << elapsedMs (q->started)
          << " ms, QueryStatus=" << statusText (results != nullptr ? results->QueryStatus : 0);
        logLine (s.str());
        return; // state intentionally leaked
    }
    q->done = true;
    q->cv.notify_all();
}

DWORD queryOptions (const std::string& mode)
{
    if (mode == "cache")
        return DNS_QUERY_NO_WIRE_QUERY;
    if (mode == "mdns")
        return DNS_QUERY_MULTICAST_ONLY;
    if (mode == "bypass")
        return DNS_QUERY_BYPASS_CACHE | DNS_QUERY_MULTICAST_ONLY;
    return DNS_QUERY_STANDARD;
}

/**
 * Runs one asynchronous DnsQueryEx and logs the outcome: synchronous result, callback result, or timeout + cancel.
 */
void runQuery (const std::wstring& name, WORD type, const std::string& mode, std::chrono::milliseconds timeout)
{
    auto* q = new QueryState;
    q->label = typeName (type) + " " + narrow (name.c_str()) + " [" + mode + "]";
    q->result.Version = DNS_QUERY_REQUEST_VERSION1;

    DNS_QUERY_REQUEST req {};
    req.Version = DNS_QUERY_REQUEST_VERSION1;
    req.QueryName = name.c_str();
    req.QueryType = type;
    req.QueryOptions = queryOptions (mode);
    req.InterfaceIndex = 0;
    req.pQueryCompletionCallback = &queryCallback;
    req.pQueryContext = q;

    q->started = Clock::now();
    DWORD status = DnsQueryEx (&req, &q->result, &q->cancel);

    {
        std::stringstream s;
        s << "query " << q->label << ": DnsQueryEx returned " << statusText (status);
        logLine (s.str());
    }

    if (status == ERROR_SUCCESS)
    {
        std::stringstream s;
        s << "  synchronous result after " << elapsedMs (q->started) << " ms, QueryStatus=" << statusText (q->result.QueryStatus);
        logLine (s.str());
        logRecords (q->result.pQueryRecords);
        if (q->result.pQueryRecords != nullptr)
            DnsRecordListFree (q->result.pQueryRecords, DnsFreeRecordList);
        delete q;
        return;
    }

    if (status != DNS_REQUEST_PENDING)
    {
        delete q;
        return;
    }

    std::unique_lock<std::mutex> lock (q->m);
    if (q->cv.wait_for (lock, timeout, [q]() { return q->done; }))
    {
        std::stringstream s;
        s << "  callback after " << elapsedMs (q->started) << " ms, QueryStatus=" << statusText (q->result.QueryStatus);
        logLine (s.str());
        logRecords (q->result.pQueryRecords);
        if (q->result.pQueryRecords != nullptr)
            DnsRecordListFree (q->result.pQueryRecords, DnsFreeRecordList);
        lock.unlock();
        delete q;
        return;
    }

    q->abandoned = true;
    lock.unlock();

    std::stringstream s;
    s << "  NO callback within " << timeout.count() << " ms; DnsCancelQuery returned " << statusText (DnsCancelQuery (&q->cancel));
    logLine (s.str());
}

// MARK: - DnsServiceResolve

struct ResolveState
{
    std::mutex m;
    std::condition_variable cv;
    bool done = false;
    bool abandoned = false; // set when we stopped waiting; the callback then only logs
    DWORD status = 0;
    PDNS_SERVICE_INSTANCE instance = nullptr;
    Clock::time_point started;
    DNS_SERVICE_CANCEL cancel {};
};

VOID WINAPI resolveCallback (DWORD status, PVOID context, PDNS_SERVICE_INSTANCE instance)
{
    auto* r = static_cast<ResolveState*> (context);
    std::lock_guard<std::mutex> lg (r->m);
    if (r->abandoned)
    {
        std::stringstream s;
        s << "LATE resolve callback after " << elapsedMs (r->started) << " ms, status=" << statusText (status) << " "
          << instanceText (instance);
        logLine (s.str());
        return; // state intentionally leaked
    }
    r->status = status;
    r->instance = instance;
    r->done = true;
    r->cv.notify_all();
}

/**
 * Runs one DnsServiceResolve and logs the outcome: callback status and instance data, or timeout + cancel.
 */
void runResolve (const std::wstring& instanceName, std::chrono::milliseconds timeout)
{
    auto* r = new ResolveState;

    DNS_SERVICE_RESOLVE_REQUEST req {};
    req.Version = DNS_QUERY_REQUEST_VERSION1;
    req.InterfaceIndex = 0;
    req.QueryName = const_cast<PWSTR> (instanceName.c_str());
    req.pResolveCompletionCallback = &resolveCallback;
    req.pQueryContext = r;

    r->started = Clock::now();
    DWORD status = DnsServiceResolve (&req, &r->cancel);
    logLine ("resolve " + narrow (instanceName.c_str()) + ": DnsServiceResolve returned " + statusText (status));

    if (status != DNS_REQUEST_PENDING && status != ERROR_SUCCESS)
    {
        delete r;
        return;
    }

    std::unique_lock<std::mutex> lock (r->m);
    if (r->cv.wait_for (lock, timeout, [r]() { return r->done; }))
    {
        std::stringstream s;
        s << "  callback after " << elapsedMs (r->started) << " ms, status=" << statusText (r->status) << " "
          << instanceText (r->instance);
        logLine (s.str());
        if (r->instance != nullptr)
            DnsServiceFreeInstance (r->instance);
        lock.unlock();
        delete r;
        return;
    }

    r->abandoned = true;
    lock.unlock();

    logLine ("  NO callback within timeout; calling DnsServiceResolveCancel");
    DWORD cancelStatus = DnsServiceResolveCancel (&r->cancel);
    std::stringstream s;
    s << "  DnsServiceResolveCancel returned " << statusText (cancelStatus) << " (timeout was " << timeout.count() << " ms)";
    logLine (s.str());
}

// MARK: - Register / cancel / deregister (raw API)

struct RegisterState
{
    std::mutex m;
    std::condition_variable cv;
    int callbacks = 0;
};

RegisterState gRegisterState; // static storage: callbacks may arrive at any time until the process exits

VOID WINAPI registerCallback (DWORD status, PVOID context, PDNS_SERVICE_INSTANCE instance)
{
    auto* st = static_cast<RegisterState*> (context);
    int n;
    {
        std::lock_guard<std::mutex> lg (st->m);
        n = ++st->callbacks;
        st->cv.notify_all();
    }
    std::stringstream s;
    s << "registerCallback #" << n << " status=" << statusText (status) << " " << instanceText (instance);
    logLine (s.str());
}

int registerCallbackCount()
{
    std::lock_guard<std::mutex> lg (gRegisterState.m);
    return gRegisterState.callbacks;
}

/// Waits until the total number of register callbacks reaches `count`. Logs and returns whether it did.
bool waitForRegisterCallbacks (int count, std::chrono::milliseconds timeout)
{
    std::unique_lock<std::mutex> lock (gRegisterState.m);
    bool reached = gRegisterState.cv.wait_for (lock, timeout, [count]() { return gRegisterState.callbacks >= count; });
    std::stringstream s;
    s << "  waited up to " << timeout.count() << " ms for register callback #" << count << ": "
      << (reached ? "received" : "NOT received") << " (total callbacks: " << gRegisterState.callbacks << ")";
    lock.unlock();
    logLine (s.str());
    return reached;
}

int cmdRegisterCancel (const std::string& serviceType, uint16_t port, const std::string& mode)
{
    if (mode != "immediate" && mode != "after")
    {
        std::cout << "mode must be 'immediate' or 'after'" << std::endl;
        return -1;
    }

    DWORD size = 0;
    GetComputerNameExW (ComputerNameDnsHostname, nullptr, &size);
    std::wstring host (size, L'\0');
    GetComputerNameExW (ComputerNameDnsHostname, &host[0], &size);
    host.resize (size);
    host += L".local";

    std::wstring instanceName = L"windns-probe-" + std::to_wstring (GetCurrentProcessId()) + L"."
                              + serviceTypeQueryName (serviceType) + L".";

    PDNS_SERVICE_INSTANCE instance = DnsServiceConstructInstance (
        instanceName.c_str(), host.c_str(), nullptr, nullptr, port, 0, 0, 0, nullptr, nullptr);
    if (instance == nullptr)
    {
        logLine ("DnsServiceConstructInstance failed: " + statusText (GetLastError()));
        return -1;
    }
    logLine ("instance name: " + narrow (instanceName.c_str()) + " host: " + narrow (host.c_str()));

    // Static storage: WinDNS may use these until the process exits. The instance is intentionally not freed.
    static DNS_SERVICE_REGISTER_REQUEST req {};
    static DNS_SERVICE_CANCEL cancel {};
    req.Version = DNS_QUERY_REQUEST_VERSION1;
    req.InterfaceIndex = 0;
    req.pServiceInstance = instance;
    req.pRegisterCompletionCallback = &registerCallback;
    req.pQueryContext = &gRegisterState;
    req.hCredentials = nullptr;
    req.unicastEnabled = FALSE;

    const std::chrono::milliseconds wait (5000);

    logLine ("DnsServiceRegister returned " + statusText (DnsServiceRegister (&req, &cancel)));

    if (mode == "after")
    {
        waitForRegisterCallbacks (1, wait);
        waitForEnter ("Registration completed. Check another browser / Wireshark: the service should be visible.");
    }

    const int callbacksBeforeCancel = registerCallbackCount();
    logLine ("DnsServiceRegisterCancel returned " + statusText (DnsServiceRegisterCancel (&cancel)));
    waitForRegisterCallbacks (callbacksBeforeCancel + 1, std::chrono::milliseconds (3000));
    waitForEnter ("After cancel. Check another browser / Wireshark: is the service visible?");

    const int callbacksBeforeDeregister = registerCallbackCount();
    logLine ("DnsServiceDeRegister returned " + statusText (DnsServiceDeRegister (&req, nullptr)));
    waitForRegisterCallbacks (callbacksBeforeDeregister + 1, wait);
    waitForEnter ("After deregister. Check Wireshark: was a goodbye (TTL 0) sent? Is the service visible?");

    return 0;
}

// MARK: - Library advertiser

int cmdAdvertiser (const std::string& serviceType, uint16_t port, const std::string& mode)
{
    if (mode != "unregister" && mode != "destroy" && mode != "txt")
    {
        std::cout << "mode must be 'unregister', 'destroy' or 'txt'" << std::endl;
        return -1;
    }

    {
        dnssd::Advertiser advertiser;
        advertiser.onAdvertiserErrorAsync ([] (const dnssd::Result& error) { logLine ("advertiser error: " + error.description()); });

        auto result = advertiser.registerService (serviceType, "windns-probe-adv", nullptr, port, { { "phase", "initial" } });
        logLine ("registerService: " + result.description());

        if (mode == "unregister")
        {
            advertiser.unregisterService();
            logLine ("unregisterService returned");
            waitForEnter ("After unregister. Check browsers: the service must NOT be visible.");
        }
        else if (mode == "txt")
        {
            result = advertiser.updateTxtRecord ({ { "phase", "updated" } });
            logLine ("updateTxtRecord: " + result.description());
            waitForEnter ("After TXT update. Check browsers: the service must be visible with phase=updated.");
        }

        logLine ("destroying advertiser");
    }
    logLine ("advertiser destroyed");
    waitForEnter ("Check browsers: the service must NOT be visible.");
    return 0;
}

// MARK: - Other commands

int cmdBrowse (const std::string& serviceType, int seconds)
{
    const std::wstring queryName = serviceTypeQueryName (serviceType);

    logLine ("PTR cache contents before browsing:");
    runQuery (queryName, DNS_TYPE_PTR, "cache", std::chrono::milliseconds (5000));

    static BrowseState st; // static storage: the cancel callback may arrive late

    DNS_SERVICE_BROWSE_REQUEST req {};
    req.Version = DNS_QUERY_REQUEST_VERSION1;
    req.InterfaceIndex = 0;
    req.QueryName = queryName.c_str();
    req.pBrowseCallback = &browseCallback;
    req.pQueryContext = &st;

    static DNS_SERVICE_CANCEL cancel {};
    DWORD status = DnsServiceBrowse (&req, &cancel);
    logLine ("DnsServiceBrowse " + narrow (queryName.c_str()) + " returned " + statusText (status));
    if (status != DNS_REQUEST_PENDING && status != ERROR_SUCCESS)
        return -1;

    std::this_thread::sleep_for (std::chrono::seconds (seconds));

    logLine ("DnsServiceBrowseCancel returned " + statusText (DnsServiceBrowseCancel (&cancel)));
    std::unique_lock<std::mutex> lock (st.m);
    bool cancelled = st.cv.wait_for (lock, std::chrono::seconds (5), []() { return st.cancelled; });
    lock.unlock();
    logLine (cancelled ? "browse cancel callback received" : "NO browse cancel callback within 5000 ms");
    return 0;
}

int cmdLiveness (const std::string& instance, int rounds, int intervalMs)
{
    const std::wstring name = wide (instance);
    const std::chrono::milliseconds interval (intervalMs);

    for (int i = 1; i <= rounds; ++i)
    {
        std::stringstream s;
        s << "===== round " << i << "/" << rounds << " =====";
        logLine (s.str());

        runResolve (name, interval);
        runQuery (name, DNS_TYPE_SRV, "cache", interval);
        runQuery (name, DNS_TYPE_SRV, "mdns", interval);
        runQuery (name, DNS_TYPE_SRV, "bypass", interval);

        if (i < rounds)
            std::this_thread::sleep_for (interval);
    }
    return 0;
}

WORD parseType (const std::string& type)
{
    if (type == "ptr") return DNS_TYPE_PTR;
    if (type == "srv") return DNS_TYPE_SRV;
    if (type == "txt") return DNS_TYPE_TEXT;
    if (type == "a") return DNS_TYPE_A;
    if (type == "aaaa") return DNS_TYPE_AAAA;
    return 0;
}

void usage()
{
    std::cout
        << "windns-probe (temporary WinDNS behaviour probe)\n"
           "\n"
           "  windns-probe browse <type> [seconds=60]\n"
           "      e.g. browse _test._tcp 120\n"
           "      Prints the PTR cache for <type>, then every browse callback with its records and TTLs.\n"
           "\n"
           "  windns-probe liveness <instance> [rounds=5] [intervalMs=5000]\n"
           "      e.g. liveness \"001122334455@SomeName._test._tcp.local\"\n"
           "      Per round: DnsServiceResolve, then SRV query from cache, via mDNS, and via mDNS bypassing the cache.\n"
           "      intervalMs is also the timeout for each call.\n"
           "\n"
           "  windns-probe query <name> <ptr|srv|txt|a|aaaa> <cache|mdns|bypass|standard> [timeoutMs=5000]\n"
           "\n"
           "  windns-probe reg-cancel <type> <port> <immediate|after>\n"
           "      immediate: register, cancel right away, then deregister.\n"
           "      after:     register, wait for the register callback, cancel, then deregister.\n"
           "      Pauses after each step so you can check another browser / Wireshark.\n"
           "\n"
           "  windns-probe adv <type> <port> <unregister|destroy|txt>\n"
           "      Uses dnssd::Advertiser: register, then immediately unregisterService(), destroy it, or updateTxtRecord().\n"
        << std::endl;
}

} // namespace

int main (int argc, char* argv[])
{
    std::vector<std::string> args (argv + 1, argv + argc);
    if (args.empty())
    {
        usage();
        return -1;
    }

    try
    {
        const std::string& cmd = args[0];

        if (cmd == "browse" && args.size() >= 2)
            return cmdBrowse (args[1], args.size() >= 3 ? std::stoi (args[2]) : 60);

        if (cmd == "liveness" && args.size() >= 2)
            return cmdLiveness (
                args[1], args.size() >= 3 ? std::stoi (args[2]) : 5, args.size() >= 4 ? std::stoi (args[3]) : 5000);

        if (cmd == "query" && args.size() >= 4)
        {
            WORD type = parseType (args[2]);
            if (type == 0)
            {
                usage();
                return -1;
            }
            runQuery (wide (args[1]), type, args[3], std::chrono::milliseconds (args.size() >= 5 ? std::stoi (args[4]) : 5000));
            return 0;
        }

        if (cmd == "reg-cancel" && args.size() >= 4)
            return cmdRegisterCancel (args[1], static_cast<uint16_t> (std::stoi (args[2])), args[3]);

        if (cmd == "adv" && args.size() >= 4)
            return cmdAdvertiser (args[1], static_cast<uint16_t> (std::stoi (args[2])), args[3]);
    }
    catch (const std::exception& e)
    {
        std::cout << "Invalid argument: " << e.what() << std::endl;
        return -1;
    }

    usage();
    return -1;
}
