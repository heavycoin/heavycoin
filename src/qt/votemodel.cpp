#include <QTimer>

#include "votemodel.h"

VoteModel::VoteModel(CVote *cvote, QObject *parent)
{
    _cvote = cvote;
    _current = 0;
    _next = 0;
    _vote = 0;
    _when = "";
    _count = 0;
    _limit = 0;

    _timer = new QTimer(this);
    connect(_timer, SIGNAL(timeout()), this, SLOT(checkVoteChanged()));
    _timer->start(500);
}

void VoteModel::checkVoteChanged()
{
    if (_current != _cvote->GetCurrent()
        || _next != _cvote->GetNext()
        || _vote != _cvote->GetVote()
        || _when != _cvote->GetWhen()
        || _count != _cvote->GetCount()
        || _limit != _cvote->GetLimit()
        || _phase != _cvote->GetPhase()
        || _supply != _cvote->GetSupply()
        || _target != _cvote->GetTarget()
        || _targetWhen != _cvote->GetTargetWhen()
        || _max != _cvote->GetMax()) {
        _current = _cvote->GetCurrent();
        _next = _cvote->GetNext();
        _vote = _cvote->GetVote();
        _when = _cvote->GetWhen();
        _count = _cvote->GetCount();
        _limit = _cvote->GetLimit();
        _phase = _cvote->GetPhase();
        _supply = _cvote->GetSupply();
        _target = _cvote->GetTarget();
        _targetWhen = _cvote->GetTargetWhen();
        _max = _cvote->GetMax();
        emit voteChanged(_current, _next, _vote, _when, _count, _limit,
                         _phase, _supply, _target, _targetWhen, _max);
    }
}
