#ifndef VOTE_H
#define VOTE_H

#include <stdint.h>
#include <string>
#include <math.h>
#include <stdio.h>

#include "main.h"
#include "uint256.h"

class CVote
{
public:
    CVote(uint16_t *vote)
    {
        _vote = vote;
        _height = 1;
        _timespan = 120; // 2 minutes
        _votespan = 10; // 10 blocks
        _limit = 2048;
        _phase = 1;
        _supply = 0;
        _target = 45000000;
        _max = 120000000;
    }

    uint16_t GetCurrent() const { return _current; }
    uint16_t GetNext() const { return _next; }
    uint16_t GetVote() const { return *_vote; }

    std::string GetWhen() const
    {
        char buf[1024];
        std::string units = "";

        float remaining = (_votespan - _height % _votespan)*_timespan;
        if (remaining < 60) {
            units = "Seconds";
            if (remaining == 1)
                units = "Second";
        }
        else if (remaining < 3600) {
            units = "Minutes";
            remaining = remaining/60;
            if (remaining == 1)
                units = "Minute";
        }
        else if (remaining < 24*3600) {
            units = "Hours";
            remaining = remaining/3600;
            if (remaining == 1)
                units = "Hour";
        }
        else {
            units = "Days";
            remaining = remaining/(24*3600);
            if (remaining == 1)
                units = "Day";
        }

        snprintf(buf, sizeof(buf), "%.1f %s", remaining, units.c_str());

        return std::string(buf);
    }

    int GetWhenSec() const
    {
        return (_votespan - _height % _votespan)*_timespan;
    }

    uint16_t GetCount() const { return _height % _votespan; }
    uint16_t GetLimit() const { return _limit; }
    uint16_t GetPhase() const { return _phase; }
    uint32_t GetSupply() const { return _supply; }
    uint32_t GetTarget() const { return _target; }

    std::string GetTargetWhen() const
    {
        char buf[1024];
        std::string units = "";

        float remaining = 0;
        if (_phase == 1) {
            if (_current)
                remaining = ((_target - _supply)/_current)*_timespan;
            else
                remaining = 0;
        }
        else if (_phase == 2)
            remaining = _target*_timespan;
        else if (_phase == 3) {
            if (_current)
                remaining = ((_max - _supply)/_current)*_timespan;
            else
                remaining = 0;
        }

        if (remaining < 60) {
            units = "Seconds";
            if (remaining == 1)
                units = "Second";
        }
        else if (remaining < 3600) {
            units = "Minutes";
            remaining = remaining/60;
            if (remaining == 1)
                units = "Minute";
        }
        else if (remaining < 24*3600) {
            units = "Hours";
            remaining = remaining/3600;
            if (remaining == 1)
                units = "Hour";
        }
        else {
            units = "Days";
            remaining = remaining/(24*3600);
            if (remaining == 1)
                units = "Day";
        }

        snprintf(buf, sizeof(buf), "%.1f %s", remaining, units.c_str());

        return std::string(buf);
    }

    uint32_t GetMax() const { return _max; }


    void UpdateParams(int height, int64 timespan, uint16_t votespan,
                      uint16_t current, uint16_t next, uint16_t limit,
                      uint16_t phase, uint32_t supply, uint32_t target, uint32_t max)
    {
        _height = (uint16_t)height;
        _timespan = (uint16_t)timespan;
        _votespan = votespan ? votespan : 1;
        _current = current;
        _next = next;
        _limit = limit;
        _phase = phase;
        _supply = supply;
        _target = target;
        _max = max;
    }

private:
    uint16_t _current;
    uint16_t _next;
    uint16_t *_vote;
    uint16_t _limit;
    uint16_t _phase;
    uint32_t _supply;
    uint32_t _target;
    uint32_t _max;

    uint16_t _height;
    uint16_t _timespan;
    uint16_t _votespan;
};

#endif // VOTE_H
