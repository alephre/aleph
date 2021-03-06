import linecache
import os
import sys
import traceback
from collections import namedtuple

# Mixins from https://github.com/mahmoud/boltons/blob/master/boltons/excutils.py


class ExceptionCauseMixin(Exception):
    """
    Exception mixin that extracts cause and traceback.

    A mixin class for wrapping an exception in another exception, or
    otherwise indicating an exception was caused by another exception.
    This is most useful in concurrent or failure-intolerant scenarios,
    where just because one operation failed, doesn't mean the remainder
    should be aborted, or that it's the appropriate time to raise
    exceptions.

    This is still a work in progress, but an example use case at the
    bottom of this module.

    NOTE: when inheriting, you will probably want to put the
    ExceptionCauseMixin first. Builtin exceptions are not good about
    calling super()
    """

    cause = None
    original_exc_info = {"type": None, "value": None, "tb": None}

    def __new__(cls, *args, **kw):
        cause = None
        if args and isinstance(args[0], Exception):
            cause, args = args[0], args[1:]
        ret = super(ExceptionCauseMixin, cls).__new__(cls, *args, **kw)
        ret.cause = cause
        if cause is None:
            return ret
        root_cause = getattr(cause, "root_cause", None)
        if root_cause is None:
            ret.root_cause = cause
        else:
            ret.root_cause = root_cause

        full_trace = getattr(cause, "full_trace", None)
        if full_trace is not None:
            ret.full_trace = list(full_trace)
            ret._tb = list(cause._tb)
            ret._stack = list(cause._stack)
            return ret

        try:
            exc_type, exc_value, exc_tb = sys.exc_info()
            ret.original_exc_info["type"] = exc_type
            ret.original_exc_info["value"] = exc_value
            ret.original_exc_info["tb"] = exc_tb
            if exc_type is None and exc_value is None:
                return ret
            if cause is exc_value or root_cause is exc_value:
                # handles when cause is the current exception or when
                # there are multiple wraps while handling the original
                # exception, but a cause was never provided
                ret._tb = _extract_from_tb(exc_tb)
                ret._stack = _extract_from_frame(exc_tb.tb_frame)
                ret.full_trace = ret._stack[:-1] + ret._tb
        finally:
            del exc_tb
        return ret

    def get_exception_text(self):

        if not self.original_exc_info["value"]:
            return self._get_message()

        fname = os.path.split(self.original_exc_info["tb"].tb_frame.f_code.co_filename)[
            1
        ]
        return f"{self.original_exc_info['type'].__name__}: {self.original_exc_info['value']} [{fname}:{self.original_exc_info['tb'].tb_lineno}]"

    def get_str(self):
        """
        Get formatted traceback and exception message.

        This function exists separately from __str__()
        because __str__() is somewhat specialized for the built-in
        traceback module's particular usage.
        """
        ret = []
        trace_str = self._get_trace_str()
        if trace_str:
            ret.extend(["Traceback (most recent call last):\n", trace_str])
        ret.append(self._get_exc_str())
        return "".join(ret)

    def _get_message(self):
        args = getattr(self, "args", [])
        if self.cause:
            args = args[1:]
        if args and args[0]:
            return args[0]
        return ""

    def _get_trace_str(self):
        if not self.cause:
            return super(ExceptionCauseMixin, self).__repr__()
        if self.full_trace:
            return "".join(traceback.format_list(self.full_trace))
        return ""

    def _get_exc_str(self, incl_name=True):
        cause_str = _format_exc(self.root_cause)
        message = self._get_message()
        ret = []
        if incl_name:
            ret = [self.__class__.__name__, ": "]
        if message:
            ret.extend([message, " (caused by ", cause_str, ")"])
        else:
            ret.extend([" caused by ", cause_str])
        return "".join(ret)

    def __str__(self):
        """Format traceback for visual representation."""
        if not self.cause:
            return super(ExceptionCauseMixin, self).__str__()
        trace_str = self._get_trace_str()
        ret = []
        if trace_str:
            message = self._get_message()
            if message:
                ret.extend([message, " --- "])
            ret.extend(
                [
                    "Wrapped traceback (most recent call last):\n",
                    trace_str,
                    self._get_exc_str(incl_name=True),
                ]
            )
            return "".join(ret)
        else:
            return self._get_exc_str(incl_name=False)


def _format_exc(exc, message=None):
    if message is None:
        message = exc
    exc_str = traceback._format_final_exc_line(exc.__class__.__name__, message)
    return exc_str.rstrip()


_BaseTBItem = namedtuple("_BaseTBItem", "filename, lineno, name, line")


class _TBItem(_BaseTBItem):
    def __repr__(self):
        ret = super(_TBItem, self).__repr__()
        ret += " <%r>" % self.frame_id
        return ret


class _DeferredLine(object):
    def __init__(self, filename, lineno, module_globals=None):
        self.filename = filename
        self.lineno = lineno
        module_globals = module_globals or {}
        self.module_globals = dict(
            [
                (k, v)
                for k, v in module_globals.items()
                if k in ("__name__", "__loader__")
            ]
        )

    def __eq__(self, other):
        return (self.lineno, self.filename) == (other.lineno, other.filename)

    def __ne__(self, other):
        return (self.lineno, self.filename) != (other.lineno, other.filename)

    def __str__(self):
        if hasattr(self, "_line"):
            return self._line
        linecache.checkcache(self.filename)
        line = linecache.getline(self.filename, self.lineno, self.module_globals)
        if line:
            line = line.strip()
        else:
            line = None
        self._line = line
        return line

    def __repr__(self):
        return repr(str(self))

    def __len__(self):
        return len(str(self))

    def strip(self):
        return str(self).strip()


def _extract_from_frame(f=None, limit=None):
    ret = []
    if f is None:
        f = sys._getframe(1)  # cross-impl yadayada
    if limit is None:
        limit = getattr(sys, "tracebacklimit", 1000)
    n = 0
    while f is not None and n < limit:
        filename = f.f_code.co_filename
        lineno = f.f_lineno
        name = f.f_code.co_name
        line = _DeferredLine(filename, lineno, f.f_globals)
        item = _TBItem(filename, lineno, name, line)
        item.frame_id = id(f)
        ret.append(item)
        f = f.f_back
        n += 1
    ret.reverse()
    return ret


def _extract_from_tb(tb, limit=None):
    ret = []
    if limit is None:
        limit = getattr(sys, "tracebacklimit", 1000)
    n = 0
    while tb is not None and n < limit:
        filename = tb.tb_frame.f_code.co_filename
        lineno = tb.tb_lineno
        name = tb.tb_frame.f_code.co_name
        line = _DeferredLine(filename, lineno, tb.tb_frame.f_globals)
        item = _TBItem(filename, lineno, name, line)
        item.frame_id = id(tb.tb_frame)
        ret.append(item)
        tb = tb.tb_next
        n += 1
    return ret
