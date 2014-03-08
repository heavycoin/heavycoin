#ifndef OVERVIEWPAGE_H
#define OVERVIEWPAGE_H

#include <QWidget>
#include <string>

namespace Ui {
    class OverviewPage;
}
class ClientModel;
class WalletModel;
class VoteModel;
class TxViewDelegate;
class TransactionFilterProxy;

class BlockChainModel;

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

/** Overview ("home") page widget */
class OverviewPage : public QWidget
{
    Q_OBJECT

public:
    explicit OverviewPage(QWidget *parent = 0);
    ~OverviewPage();

    void setClientModel(ClientModel *clientModel);
    void setWalletModel(WalletModel *walletModel);
    void setVoteModel(VoteModel *voteModel);
    void showOutOfSyncWarning(bool fShow);

public slots:
    void setBalance(qint64 balance, qint64 unconfirmedBalance, qint64 immatureBalance);
    void setVote(quint16 current, quint16 next, quint16 vote,
                 std::string when, quint16 count, quint16 limit,
                 quint16 phase, quint32 supply, quint32 target, std::string targetWhen,
                 quint32 max);

signals:
    void transactionClicked(const QModelIndex &index);

private:
    Ui::OverviewPage *ui;
    ClientModel *clientModel;
    WalletModel *walletModel;
    VoteModel *voteModel;
    qint64 currentBalance;
    qint64 currentUnconfirmedBalance;
    qint64 currentImmatureBalance;

    TxViewDelegate *txdelegate;
    TransactionFilterProxy *filter;

private slots:
    void updateDisplayUnit();
    void handleTransactionClicked(const QModelIndex &index);
    void updateAlerts(const QString &warnings);
    void updateVotingShow(bool fShow);
    void updateSupplyShow(bool fShow);
};

#endif // OVERVIEWPAGE_H
