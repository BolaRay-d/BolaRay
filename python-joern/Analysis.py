import time

from joern.all import JoernSteps


class Analysis(object):

    def __init__(self, port):
        '''
        Constructor
        '''
        self.j = JoernSteps()
        self.j.setGraphDbURL('http://localhost:%d/db/data/' % (int(port)))
        self.j.connectToDatabase()

    def runTimedQuery(self, query):
        start = time.time()
        res = None
        try:
            if query:
                res = self.j.runGremlinQuery(query)

        except Exception as err:
            print("Caught exception:", type(err), err)

        elapsed = time.time() - start

        timestr = "Query done in %f seconds." % (elapsed)

        return (res, timestr)
