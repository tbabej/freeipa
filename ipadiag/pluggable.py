from ipalib.frontend import Plugin

class BaseDiagnosePlugin(Plugin):
    """
    Base class for diagnosis plugins.
    """

    def run(self, args):
        print "Executed: %s" % args


    def is_applicable(self):
        """
        Detects whether diagnosis should be run on the instance.
        """
        pass


class Reporter(BaseDiagnosePlugin):
    """
    Base class for reporters plugins.
    """

    def is_applicable(self):
        """
        Detects whether diagnosis should be run on the instance.
        """
        pass

    def report(self):
        """
        Main body of the diagnosis script.
        """
        raise NotImplementedError


class Diagnosis(BaseDiagnosePlugin):
    """
    Base class for diagnose plugins.
    """

    options = None
    require_root = False
    description = ''

    def diagnose(self):
        """
        Main body of the diagnosis script.
        """
        raise NotImplementedError
