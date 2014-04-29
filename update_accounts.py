# Removes duplicate nicknames (issue99).
#
# To run this script:
#  - Make sure App Engine library (incl. yaml) is in PYTHONPATH.
#  - Make sure that the remote API is included in app.yaml.
#  - Run "tools/appengine_console.py APP_ID".
#  - Import this module.
#  - update_accounts.run() updates accounts.
#  - Use the other two functions to fetch accounts or find duplicates
#    without any changes to the datastore.


from google.appengine.ext import db

from codereview import models


def fetch_accounts():
    query = models.Account.all()
    accounts = {}
    results = query.fetch(100)
    while results:
        last = None
        for account in results:
            if account.lower_nickname in accounts:
                accounts[account.lower_nickname].append(account)
            else:
                accounts[account.lower_nickname] = [account]
            last = account
        if last is None:
            break
        results = models.Account.all().filter('__key__ >',
                                              last.key()).fetch(100)
    return accounts


def find_duplicates(accounts):
    tbd = []
    while accounts:
        _, entries = accounts.popitem()
        if len(entries) > 1:
            # update accounts, except the fist: it's the lucky one
            for num, account in enumerate(entries[1:]):
                account.nickname = '%s%d' % (account.nickname, num+1)
                account.lower_nickname = account.nickname.lower()
                account.fresh = True  # display "change nickname..."
                tbd.append(account)
    return tbd


def run():
    accounts = fetch_accounts()
    print '%d accounts fetched' % len(accounts)

    tbd = find_duplicates(accounts)
    print 'Updating %d accounts' % len(tbd)

    db.put(tbd)

    print 'Updated accounts:'
    for account in tbd:
        print ' %s' % account.email
