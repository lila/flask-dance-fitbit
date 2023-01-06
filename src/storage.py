# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""google firestore token backend for fitbit auth tokens

implements a storage backend for firebase to store oauth tokens
"""
from flask_dance.consumer.storage import BaseStorage
import firebase_admin
from firebase_admin import firestore

# by default looks for a file called service-account.json in the local
# directory with the contents of the service account secrets.
firebase_admin.initialize_app()
db = firestore.client()


class FirestoreStorage(BaseStorage):
    """OAuth token backend implementation for FireStore"""

    def __init__(self, collection):
        super(FirestoreStorage, self).__init__()

        self.collection = db.collection(collection)
        self.user = None

    def get(self, blueprint):

        if self.user:
            doc_ref = self.collection.document(self.user)
            doc = doc_ref.get()

            if doc.exists:
                return dict(doc.to_dict())

        return {}

    def set(self, blueprint, token):

        if self.user:
            self.collection.document(self.user).set(token)

    def delete(self, blueprint):

        if self.user:
            self.collection.document(self.user).delete()

    def all_users(self):
        return [doc.id for doc in self.collection.stream()]

    def save(self, user, token):
        if user:
            self.collection.document(user).set(token)
