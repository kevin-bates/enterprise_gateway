# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.
"""Jupyter websocket personality for the Kernel Gateway"""

import os
from kernel_gateway.jupyter_websocket import JupyterWebsocketPersonality
from ..services.admin.handlers import default_handlers as default_admin_handlers
from .handlers import default_handlers as default_spec_handlers
from notebook.utils import url_path_join


class JupyterEnterpriseWebsocketPersonality(JupyterWebsocketPersonality):
    """Extends JKG's websocket personality with JEG's admin API.
    """

    def init_configurables(self):
        super(JupyterEnterpriseWebsocketPersonality, self).init_configurables()

    def create_request_handlers(self):
        """Create default Jupyter handlers and redefine them off of the
        base_url path. Assumes init_configurables() has already been called.
        """
        kg_handlers = super(JupyterEnterpriseWebsocketPersonality, self).create_request_handlers()
        eg_handlers = []
        # append tuples for the enterprise gateway admin endpoints
        for handler in (
            default_spec_handlers +
            default_admin_handlers
        ):
            # Create a new handler pattern rooted at the base_url
            pattern = url_path_join('/', self.parent.base_url, handler[0])
            # Some handlers take args, so retain those in addition to the
            # handler class ref
            new_handler = tuple([pattern] + list(handler[1:]))
            eg_handlers.append(new_handler)

        # We must prepend our handlers to JKG's else the generic Not Found "catchall" handler regex
        # intercepts our endpoints.
        return eg_handlers + kg_handlers

    def shutdown(self):
        super(JupyterEnterpriseWebsocketPersonality, self).shutdown()


def create_personality(*args, **kwargs):
    return JupyterEnterpriseWebsocketPersonality(*args, **kwargs)
