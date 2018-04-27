# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.
"""Tornado handlers for kernel CRUD and communication."""

import os
import json
import tornado
import notebook.base.handlers as notebook_handlers
from tornado import gen, web
from jupyter_client.jsonutil import date_default
from kernel_gateway.mixins import TokenAuthorizationMixin, CORSMixin, JSONErrorsMixin


class UsersHandler(TokenAuthorizationMixin,
                        CORSMixin,
                        JSONErrorsMixin,
                        notebook_handlers.APIHandler):
    """
    Extends the notebook API handler with token auth, CORS, and JSON errors.
    """

    @web.authenticated
    @gen.coroutine
    def get(self):
        """Returns the list of running kernels, ordered by user

        Raises
        ------
        tornado.web.HTTPError
            403 Forbidden if kernel listing is disabled
        """
        if not self.settings.get('kg_list_kernels'):
            raise tornado.web.HTTPError(403, 'Forbidden')

        km = self.kernel_manager
        kernels = yield gen.maybe_future(km.list_kernels())

        # have the complete list of running kernels, now sort by username and return
        kernels_by_users = dict()
        for kernel in kernels:
            user_name = kernel['user_name']
            kbu = kernels_by_users.get(user_name, [])
            kbu.append(kernel)
            kernels_by_users[user_name] = kbu

        self.finish(json.dumps(kernels_by_users, default=date_default))


    def options(self, **kwargs):
        """Method for properly handling CORS pre-flight"""
        self.finish()


class UserHandler(TokenAuthorizationMixin,
                    CORSMixin,
                    JSONErrorsMixin,
                    notebook_handlers.APIHandler):
    """
    Extends the notebook kernel handler with token auth, CORS, and JSON errors.
    """

    @web.authenticated
    @gen.coroutine
    def get(self, username):
        """Returns the list of running kernels, ordered by user

        Raises
        ------
        tornado.web.HTTPError
            403 Forbidden if kernel listing is disabled
        """
        if not self.settings.get('kg_list_kernels'):
            raise tornado.web.HTTPError(403, 'Forbidden')

        # FIXME - there will be a better way to do this
        km = self.kernel_manager
        kernels = yield gen.maybe_future(km.list_kernels())

        # have the complete list of running kernels, now sort by username and return
        kernels_by_user = []
        for kernel in kernels:
            if username == kernel['user_name']:
                kernels_by_user.append(kernel)

        self.finish(json.dumps(kernels_by_user, default=date_default))

    def options(self, **kwargs):
        """Method for properly handling CORS pre-flight"""
        self.finish()


#-----------------------------------------------------------------------------
# URL to handler mappings
#-----------------------------------------------------------------------------


_username_regex = r"(?P<username>\w)"

default_handlers = [
    (r"/admin/users", UsersHandler),
    (r"/admin/users/%s" % _username_regex, UserHandler),
]