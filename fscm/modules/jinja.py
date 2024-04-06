import typing as t
import logging

log = logging.getLogger(__name__)

try:
    import jinja2
    HAS_JINJA = True

    from jinja2 import Environment  # noqa

    class RemoteLoader(jinja2.BaseLoader):
        """
        This reuses the existing parent-file-fetching logic (see Parent.get_file() in
         `fscm.remote` to support getting jinja templates from a remote Parent.
        """
        def __init__(self, parent):
            self.parent = parent

        def get_source(self, environment, template) -> (str, str, t.Callable):
            try:
                source = self.parent.get_file(template).decode()
            except Exception as e:
                log.exception("error requesting jinja template from parent")
                raise jinja2.TemplateNotFound(template) from e
            return source, template, lambda: False
except ImportError:
    HAS_JINJA = False
    jinja2 = object()  # type: ignore
    class RemoteLoader:  # noqa
        pass
