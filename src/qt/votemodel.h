#ifndef VOTEMODEL_H
#define VOTEMODEL_H

#include <QObject>
#include <string>

#include "vote.h"

QT_BEGIN_NAMESPACE
class QTimer;
QT_END_NAMESPACE

class VoteModel : public QObject
{
    Q_OBJECT

public:
    explicit VoteModel(CVote *cvote, QObject *parent = 0);

private:
    quint16 _current;
    quint16 _next;
    quint16 _vote;
    quint16 _count;
    quint16 _limit;
    std::string _when;
    quint16 _phase;
    quint32 _supply;
    quint32 _target;
    std::string _targetWhen;
    quint32 _max;

    CVote *_cvote;
    QTimer *_timer;

signals:
    void voteChanged(quint16 current, quint16 next, quint16 vote,
                     std::string when, quint16 count, quint16 limit,
                     quint16 phase, quint32 supply, quint32 target,
                     std::string targetWhen, quint32 max);

public slots:
    void checkVoteChanged();
};

#endif // VOTEMODEL_H
