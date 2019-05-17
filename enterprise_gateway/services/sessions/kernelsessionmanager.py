# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.

import copy
import getpass
import json
import os
import threading

from ipython_genutils.py3compat import (bytes_to_str, str_to_bytes)
from jupyter_core.paths import jupyter_data_dir
from notebook.services.contents.manager import ContentsManager
from notebook.services.contents.filemanager import FileContentsManager
from traitlets import Type, Bool, default
from traitlets.config.configurable import LoggingConfigurable

KERNEL_SESSIONS_DIR_NAME = "kernel_sessions"
KERNEL_SESSIONS_PATH_NAME = KERNEL_SESSIONS_DIR_NAME + "/sessions.json"
CM_DIRECTORY = 'directory'
CM_FILE = 'file'
CM_FORMAT_TEXT = 'text'
CM_FORMAT_JSON = 'json'

kernels_lock = threading.Lock()

kernel_session_root = os.getenv('EG_KERNEL_SESSION_LOCATION', jupyter_data_dir())


class KernelSessionManager(LoggingConfigurable):
    """ KernelSessionManager is used to persist and load kernel sessions from persistent storage.

        KernelSessionManager provides the basis for an HA solution.  It loads the complete set of persisted kernel
        sessions during construction.  Following construction the parent object calls start_sessions to allow
        Enterprise Gateway to validate that all loaded sessions are still valid.  Those that it cannot 'revive'
        are marked for deletion and the in-memory dictionary is updated - and the entire collection is written
        to store (file or database).

        As kernels are created and destroyed, the KernelSessionManager is called upon to keep kernel session
        state consistent.
    """

    # Session Persistence
    session_persistence_env = 'EG_KERNEL_SESSION_PERSISTENCE'
    session_persistence_default_value = False
    enable_persistence = Bool(session_persistence_default_value, config=True,
                              help="""Enable kernel session persistence (True or False). Default = False
                              (EG_KERNEL_SESSION_PERSISTENCE env var)""")

    @default('enable_persistence')
    def session_persistence_default(self):
        return bool(os.getenv(self.session_persistence_env,
                              str(self.session_persistence_default_value)).lower() == 'true')

    session_persistence_class = Type(
        default_value=FileContentsManager,
        klass=ContentsManager,
        config=True,
        help="""The session persistence manager class to use."""
    )

    def __init__(self, kernel_manager, **kwargs):
        super(KernelSessionManager, self).__init__(**kwargs)
        self.kernel_manager = kernel_manager
        self._sessions = dict()
        self._sessionsByUser = dict()

        if self.enable_persistence:
            # A bit of a hack to get around the fact that FileContentsManager wants to place things
            # under the notebook_dir or cwd, while we'd rather use jupyter_data_dir (or wherever user
            # specifies).  The reason we can't set root_dir via the FileContentsManager configuration
            # is because that could side-affect installations where FileContentsManager is also being
            # used by the notebook server.
            if self.session_persistence_class.__name__ == FileContentsManager.__name__:
                kwargs['root_dir'] = kernel_session_root  # this location must exist

            self.persistence_manager = self.session_persistence_class(**kwargs)

            # Create the kernel_sessions "directory", if not present.  Then load the sessions.
            if not self.persistence_manager.dir_exists(KERNEL_SESSIONS_DIR_NAME):
                # Commits the sessions dictionary to persistent store.  Caller is responsible for single-threading call.
                model = dict()
                model['type'] = 'directory'
                model['format'] = 'text'
                self.persistence_manager.save(model=model, path=KERNEL_SESSIONS_DIR_NAME)

            self._load_sessions()

    def create_session(self, kernel_id, **kwargs):
        """Creates a session associated with this kernel.

        All items associated with the active kernel's state are saved.

        Parameters
        ----------
        kernel_id : str
            The uuid string associated with the active kernel

        **kwargs : optional
            Information used for the launch of the kernel

        """
        km = self.kernel_manager.get_kernel(kernel_id)

        # Compose the kernel_session entry
        kernel_session = dict()
        kernel_session['kernel_id'] = kernel_id
        kernel_session['username'] = KernelSessionManager.get_kernel_username(**kwargs)
        kernel_session['kernel_name'] = km.kernel_name

        # Build the inner dictionaries: connection_info, process_proxy and add to kernel_session
        kernel_session['connection_info'] = km.get_connection_info()
        kernel_session['launch_args'] = kwargs.copy()
        kernel_session['process_info'] = km.process_proxy.get_process_info() if km.process_proxy else {}
        self._save_session(kernel_id, kernel_session)

    def refresh_session(self, kernel_id):
        """Refreshes the session from its persisted state. Called on kernel restarts."""
        self.log.debug("Refreshing kernel session for id: {}".format(kernel_id))
        km = self.kernel_manager.get_kernel(kernel_id)

        # Compose the kernel_session entry
        kernel_session = self._sessions[kernel_id]

        # Build the inner dictionaries: connection_info, process_proxy and add to kernel_session
        kernel_session['connection_info'] = km.get_connection_info()
        kernel_session['process_info'] = km.process_proxy.get_process_info() if km.process_proxy else {}
        self._save_session(kernel_id, kernel_session)

    def _save_session(self, kernel_id, kernel_session):
        # Write/commit the addition, update dictionary
        kernels_lock.acquire()
        try:
            self._sessions[kernel_id] = kernel_session
            username = kernel_session['username']
            if username not in self._sessionsByUser:
                self._sessionsByUser[username] = []
                self._sessionsByUser[username].append(kernel_id)
            else:
                # Only append if not there yet (e.g. restarts will be there already)
                if kernel_id not in self._sessionsByUser[username]:
                    self._sessionsByUser[username].append(kernel_id)
            self._commit_sessions()  # persist changes
        finally:
            kernels_lock.release()

    def _load_sessions(self):
        if self.enable_persistence:
            # Read directory and initialize _sessions member.  Must be called from constructor.
            dir_model = self.persistence_manager.get(KERNEL_SESSIONS_DIR_NAME)
            for f in dir_model['content']:
                if f['path'] == KERNEL_SESSIONS_PATH_NAME:
                    file_model = self.persistence_manager.get(f['path'], format=CM_FORMAT_TEXT)
                    if file_model['content']:
                        self._sessions = self._post_load_transformation(json.loads(file_model['content']))

    def start_sessions(self):
        """ Attempt to start persisted sessions.

        Determines if session startup was successful.  If unsuccessful, the session is removed
        from persistent storage.
        """
        if self.enable_persistence:
            sessions_to_remove = []
            for kernel_id, kernel_session in self._sessions.items():
                self.log.info("Attempting startup of persisted kernel session for id: %s..." % kernel_id)
                if self._start_session(kernel_session):
                    self.log.info("Startup of persisted kernel session for id '{}' was successful.  Client should "
                                  "reconnect kernel.".format(kernel_id))
                else:
                    sessions_to_remove.append(kernel_id)
                    self.log.warn("Startup of persisted kernel session for id '{}' was not successful.  Check if "
                                  "client is still active and restart kernel.".format(kernel_id))

            self._delete_sessions(sessions_to_remove)

    def _start_session(self, kernel_session):
        # Attempt to start kernel from persisted state.  if started, record kernel_session in dictionary
        # else delete session
        kernel_id = kernel_session['kernel_id']
        kernel_started = self.kernel_manager.start_kernel_from_session(
            kernel_id=kernel_id,
            kernel_name=kernel_session['kernel_name'],
            connection_info=kernel_session['connection_info'],
            process_info=kernel_session['process_info'],
            launch_args=kernel_session['launch_args'])
        if not kernel_started:
            return False

        return True

    def delete_session(self, kernel_id):
        """Removes saved session associated with kernel_id from dictionary and persisted storage."""
        self._delete_sessions([kernel_id])

        if self.enable_persistence:
            self.log.info("Deleted persisted kernel session for id: %s" % kernel_id)

    def _delete_sessions(self, kernel_ids):
        # Remove unstarted sessions and rewrite
        kernels_lock.acquire()
        try:
            for kernel_id in kernel_ids:
                # Prior to removing session, update the per User list
                kernel_session = self._sessions[kernel_id]
                username = kernel_session['username']
                if username in self._sessionsByUser and kernel_id in self._sessionsByUser[username]:
                    self._sessionsByUser[username].remove(kernel_id)
                self._sessions.pop(kernel_id, None)

            self._commit_sessions()  # persist changes
        finally:
            kernels_lock.release()

    def _commit_sessions(self):
        if self.enable_persistence:
            # Commits the sessions dictionary to persistent store.  Caller is responsible for single-threading call.
            model = dict()
            model['type'] = 'file'
            model['content'] = json.dumps(self._pre_save_transformation(self._sessions))
            model['format'] = 'text'
            self.persistence_manager.save(model=model, path=KERNEL_SESSIONS_PATH_NAME)

    @staticmethod
    def _pre_save_transformation(sessions):
        sessions_copy = copy.deepcopy(sessions)
        for kernel_id, session in sessions_copy.items():
            if session.get('connection_info'):
                info = session['connection_info']
                key = info.get('key')
                if key:
                    info['key'] = bytes_to_str(key)

        return sessions_copy

    @staticmethod
    def _post_load_transformation(sessions):
        sessions_copy = copy.deepcopy(sessions)
        for kernel_id, session in sessions_copy.items():
            if session.get('connection_info'):
                info = session['connection_info']
                key = info.get('key')
                if key:
                    info['key'] = str_to_bytes(key)

        return sessions_copy

    def active_sessions(self, username):
        """ Returns the number of active sessions for the given username.

        Parameters
        ----------
        username : str
            The username associated with the active session

        Returns
        -------
        int corresponding to the number of active sessions associated with given user
        """
        if username in self._sessionsByUser:
            return len(self._sessionsByUser[username])
        return 0

    @staticmethod
    def get_kernel_username(**kwargs):
        """ Returns the kernel's logical username from env dict.

        Checks the process env for KERNEL_USERNAME.  If set, that value is returned, else KERNEL_USERNAME is
        initialized to the current user and that value is returned.

        Parameters
        ----------
        kwargs : dict from which request env is accessed.

        Returns
        -------
        str indicating kernel username
        """
        # Get the env
        env_dict = kwargs.get('env', {})

        # Ensure KERNEL_USERNAME is set
        kernel_username = env_dict.get('KERNEL_USERNAME')
        if kernel_username is None:
            kernel_username = getpass.getuser()
            env_dict['KERNEL_USERNAME'] = kernel_username

        return kernel_username
