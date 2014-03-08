#include "overviewpage.h"
#include "ui_overviewpage.h"

#include "clientmodel.h"
#include "walletmodel.h"
#include "votemodel.h"
#include "bitcoinunits.h"
#include "optionsmodel.h"
#include "transactiontablemodel.h"
#include "transactionfilterproxy.h"
#include "guiutil.h"
#include "guiconstants.h"

#include "monitoreddatamapper.h"
#include "optionsmodel.h"


#include <QAbstractItemDelegate>
#include <QPainter>

#define DECORATION_SIZE 64
#define NUM_ITEMS 4

class TxViewDelegate : public QAbstractItemDelegate
{
    Q_OBJECT
public:
    TxViewDelegate(): QAbstractItemDelegate(), unit(BitcoinUnits::BTC)
    {

    }

    inline void paint(QPainter *painter, const QStyleOptionViewItem &option,
                      const QModelIndex &index ) const
    {
        painter->save();

        QIcon icon = qvariant_cast<QIcon>(index.data(Qt::DecorationRole));
        QRect mainRect = option.rect;
        QRect decorationRect(mainRect.topLeft(), QSize(DECORATION_SIZE, DECORATION_SIZE));
        int xspace = DECORATION_SIZE + 8;
        int ypad = 6;
        int halfheight = (mainRect.height() - 2*ypad)/2;
        QRect amountRect(mainRect.left() + xspace, mainRect.top()+ypad, mainRect.width() - xspace, halfheight);
        QRect addressRect(mainRect.left() + xspace, mainRect.top()+ypad+halfheight, mainRect.width() - xspace, halfheight);
        icon.paint(painter, decorationRect);

        QDateTime date = index.data(TransactionTableModel::DateRole).toDateTime();
        QString address = index.data(Qt::DisplayRole).toString();
        qint64 amount = index.data(TransactionTableModel::AmountRole).toLongLong();
        bool confirmed = index.data(TransactionTableModel::ConfirmedRole).toBool();
        QVariant value = index.data(Qt::ForegroundRole);
        QColor foreground = option.palette.color(QPalette::Text);
        if(value.canConvert<QBrush>())
        {
            QBrush brush = qvariant_cast<QBrush>(value);
            foreground = brush.color();
        }

        painter->setPen(foreground);
        painter->drawText(addressRect, Qt::AlignLeft|Qt::AlignVCenter, address);

        if(amount < 0)
        {
            foreground = COLOR_NEGATIVE;
        }
        else if(!confirmed)
        {
            foreground = COLOR_UNCONFIRMED;
        }
        else
        {
            foreground = option.palette.color(QPalette::Text);
        }
        painter->setPen(foreground);
        QString amountText = BitcoinUnits::formatWithUnit(unit, amount, true);
        if(!confirmed)
        {
            amountText = QString("[") + amountText + QString("]");
        }
        painter->drawText(amountRect, Qt::AlignRight|Qt::AlignVCenter, amountText);

        painter->setPen(option.palette.color(QPalette::Text));
        painter->drawText(amountRect, Qt::AlignLeft|Qt::AlignVCenter, GUIUtil::dateTimeStr(date));

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const
    {
        return QSize(DECORATION_SIZE, DECORATION_SIZE);
    }

    int unit;

};
#include "overviewpage.moc"

OverviewPage::OverviewPage(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::OverviewPage),
    clientModel(0),
    walletModel(0),
    voteModel(0),
    currentBalance(-1),
    currentUnconfirmedBalance(-1),
    currentImmatureBalance(-1),
    txdelegate(new TxViewDelegate()),
    filter(0)
{
    ui->setupUi(this);

    // Recent transactions
    ui->listTransactions->setItemDelegate(txdelegate);
    ui->listTransactions->setIconSize(QSize(DECORATION_SIZE, DECORATION_SIZE));
    ui->listTransactions->setMinimumHeight(NUM_ITEMS * (DECORATION_SIZE + 2));
    ui->listTransactions->setAttribute(Qt::WA_MacShowFocusRect, false);

    connect(ui->listTransactions, SIGNAL(clicked(QModelIndex)), this, SLOT(handleTransactionClicked(QModelIndex)));

    // init "out of sync" warning labels
    ui->labelWalletStatus->setText("(" + tr("out of sync") + ")");
    ui->labelVoteStatus->setText("(" + tr("out of sync") + ")");
    ui->labelTransactionsStatus->setText("(" + tr("out of sync") + ")");

    // start with displaying the "out of sync" warnings
    showOutOfSyncWarning(true);
}

void OverviewPage::handleTransactionClicked(const QModelIndex &index)
{
    if(filter)
        emit transactionClicked(filter->mapToSource(index));
}

OverviewPage::~OverviewPage()
{
    delete ui;
}

void OverviewPage::setBalance(qint64 balance, qint64 unconfirmedBalance, qint64 immatureBalance)
{
    int unit = walletModel->getOptionsModel()->getDisplayUnit();
    currentBalance = balance;
    currentUnconfirmedBalance = unconfirmedBalance;
    currentImmatureBalance = immatureBalance;
    ui->labelBalance->setText(BitcoinUnits::formatWithUnit(unit, balance));
    ui->labelUnconfirmed->setText(BitcoinUnits::formatWithUnit(unit, unconfirmedBalance));
    ui->labelImmature->setText(BitcoinUnits::formatWithUnit(unit, immatureBalance));

    // only show immature (newly mined) balance if it's non-zero, so as not to complicate things
    // for the non-mining users
    bool showImmature = immatureBalance != 0;
    if (showImmature) {
        ui->labelImmature->setStyleSheet("QLabel { color : black; }");
        ui->labelImmatureText->setStyleSheet("QLabel { color : black; }");
    }
    else {
        ui->labelImmature->setStyleSheet("QLabel { color : transparent; }");
        ui->labelImmatureText->setStyleSheet("QLabel { color : transparent; }");
    }
}

void OverviewPage::setVote(quint16 current, quint16 next, quint16 vote,
                           std::string when, quint16 count, quint16 limit,
                           quint16 phase, quint32 supply, quint32 target,
                           std::string targetWhen, quint32 max)
{
    ui->labelCurrentReward->setText(QString::number(current) + " HVC");
    if (count > 0)
        ui->labelNextReward->setText(QString::number(next) +" HVC");
    else
        ui->labelNextReward->setText("N/A");

    if (count > 1)
        ui->labelVoteCount->setText("(averaged " + QString::number(count)  + " votes)");
    else if (count)
        ui->labelVoteCount->setText("(1 vote)");
    else
        ui->labelVoteCount->setText("(no votes)");

    ui->labelVoteCount->setStyleSheet("QLabel { color : gray; }");

    ui->labelWhen->setText(QString(when.c_str()));
    ui->labelYourVote->setText(QString::number(vote) + " HVC");
    ui->labelVoteLimit->setText("(max " + QString::number(limit)  + ")");
    ui->labelVoteLimit->setStyleSheet("QLabel { color : gray; }");

    if (phase == 1) {
        ui->labelPhase->setText("Mint");
        ui->labelPhaseInfo->setText("(votes affect mint duration)");
        ui->labelTarget->setText(QString::number(target) + " HVC");
    }
    else if (phase == 2) {
        ui->labelPhase->setText("Limit");
        ui->labelPhaseInfo->setText("(votes affect max money supply)");
        ui->labelTarget->setText(QString::number(target) + " blocks");
    }
    else if (phase == 3) {
        ui->labelPhase->setText("Sustain");
        ui->labelPhaseInfo->setText("(votes affect sustain duration)");
        ui->labelTarget->setText(QString::number(target) + " HVC");
    }
    ui->labelPhaseInfo->setStyleSheet("QLabel { color : gray; }");


    ui->labelCurrentSupply->setText(QString::number(supply) + " HVC");
    ui->labelMaxSupply->setText(QString::number(max) + " HVC");
    ui->labelTargetWhen->setText("(" + QString(targetWhen.c_str()) + ")");
    ui->labelTargetWhen->setStyleSheet("QLabel { color : gray; }");

}

void OverviewPage::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if(model)
    {
        // Show warning if this is a prerelease version
        connect(model, SIGNAL(alertsChanged(QString)), this, SLOT(updateAlerts(QString)));
        updateAlerts(model->getStatusBarWarnings());
    }
}

void OverviewPage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
    if(model && model->getOptionsModel())
    {
        // Set up transaction list
        filter = new TransactionFilterProxy();
        filter->setSourceModel(model->getTransactionTableModel());
        filter->setLimit(NUM_ITEMS);
        filter->setDynamicSortFilter(true);
        filter->setSortRole(Qt::EditRole);
        filter->sort(TransactionTableModel::Status, Qt::DescendingOrder);

        ui->listTransactions->setModel(filter);
        ui->listTransactions->setModelColumn(TransactionTableModel::ToAddress);

        // Keep up to date with wallet
        setBalance(model->getBalance(), model->getUnconfirmedBalance(), model->getImmatureBalance());
        connect(model, SIGNAL(balanceChanged(qint64, qint64, qint64)), this, SLOT(setBalance(qint64, qint64, qint64)));

        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));
        connect(model->getOptionsModel(), SIGNAL(votingShowChanged(bool)), this, SLOT(updateVotingShow(bool)));
        connect(model->getOptionsModel(), SIGNAL(supplyShowChanged(bool)), this, SLOT(updateSupplyShow(bool)));
    }

    // update the display unit, to not use the default ("BTC")
    updateDisplayUnit();
    if (model->getOptionsModel()) {
        updateVotingShow(model->getOptionsModel()->getShowVotingOverview());
        updateSupplyShow(model->getOptionsModel()->getShowSupplyOverview());
    }
}

void OverviewPage::setVoteModel(VoteModel *model)
{
    this->voteModel = model;
    connect(model, SIGNAL(voteChanged(quint16, quint16, quint16, std::string, quint16, quint16,
                                      quint16, quint32, quint32, std::string, quint32)),
                          this, SLOT(setVote(quint16, quint16, quint16, std::string, quint16,
                                             quint16, quint16, quint32, quint32, std::string,
                                             quint32)));
}

void OverviewPage::updateDisplayUnit()
{
    if(walletModel && walletModel->getOptionsModel())
    {
        if(currentBalance != -1)
            setBalance(currentBalance, currentUnconfirmedBalance, currentImmatureBalance);

        // Update txdelegate->unit with the current unit
        txdelegate->unit = walletModel->getOptionsModel()->getDisplayUnit();

        ui->listTransactions->update();
    }
}

void OverviewPage::updateAlerts(const QString &warnings)
{
    this->ui->labelAlerts->setVisible(!warnings.isEmpty());
    this->ui->labelAlerts->setText(warnings);
}

void OverviewPage::showOutOfSyncWarning(bool fShow)
{
    ui->labelWalletStatus->setVisible(fShow);
    ui->labelVoteStatus->setVisible(fShow);
    ui->labelSupplyStatus->setVisible(fShow);
    ui->labelTransactionsStatus->setVisible(fShow);
}

void OverviewPage::updateVotingShow(bool fShow)
{
    ui->frameVoting->setVisible(fShow);
}

void OverviewPage::updateSupplyShow(bool fShow)
{
    ui->frameSupply->setVisible(fShow);
}
