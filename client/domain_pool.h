#pragma once

#include <string>
#include <vector>
#include <common/commands.h>
#include <cstdlib>
#include <cstring>

std::string GetIPAddress(const char* hostName);

class DomainPool
{
private:
    char Address[100]; // ˳ȺCONNECT_ADDRESSƥ
    std::vector<std::string> HostList;
    std::vector<std::string> IPList;

    static std::string SelectFrom(const std::vector<std::string>& list)
    {
        if (list.empty()) return "";
        auto n = rand() % list.size();
        return list[n];
    }

    void Assign(const char* addr)
    {
        memset(Address, 0, sizeof(Address));
        HostList.clear();
        IPList.clear();
        if (!addr) return;

        strcpy_s(Address, addr);
        HostList = StringToVector(Address, ';');
        if (HostList.empty()) HostList.push_back("");

        for (const auto& host : HostList) {
            auto resolved = GetIPAddress(host.c_str());
            IPList.push_back(resolved.empty() ? host : resolved);
        }
    }

public:
    DomainPool()
    {
        memset(Address, 0, sizeof(Address));
    }

    DomainPool(const char* addr)
    {
        Assign(addr);
    }

    DomainPool& operator=(const char* addr)
    {
        Assign(addr);
        return *this;
    }

    std::string SelectIP() const
    {
        return SelectFrom(IPList);
    }

    std::string SelectHost(bool preferResolved = false) const
    {
        return preferResolved ? SelectFrom(IPList) : SelectFrom(HostList);
    }

    std::vector<std::string> GetIPList() const
    {
        return IPList;
    }
};
