import os
import re
import json
import uuid
import datetime
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from .config import MONGODB_URI, DB_NAME

# Setup local JSON fallback directories
if os.environ.get('VERCEL') == '1':
    # Vercel filesystem is read-only except /tmp
    FALLBACK_DATA_DIR = '/tmp/data'
else:
    FALLBACK_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')

class FallbackCollection:
    def __init__(self, name, data_dir):
        self.name = name
        self.file_path = os.path.join(data_dir, f"{name}.json")
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
        if not os.path.exists(self.file_path):
            with open(self.file_path, 'w') as f:
                json.dump([], f)

    def _read(self):
        try:
            with open(self.file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[-] Error reading fallback JSON file {self.name}: {e}")
            return []

    def _write(self, data):
        try:
            with open(self.file_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            print(f"[-] Error writing fallback JSON file {self.name}: {e}")

    def _matches_filter(self, doc, query_filter):
        if not query_filter:
            return True
        for key, val in query_filter.items():
            if key == '$or':
                if not any(self._matches_filter(doc, sub) for sub in val):
                    return False
                continue
            
            # Sub-property search/dictionary operators
            if isinstance(val, dict):
                op = list(val.keys())[0]
                target_val = val[op]
                if op == '$regex':
                    try:
                        pattern = re.compile(target_val, re.IGNORECASE)
                        if key not in doc or not pattern.search(str(doc[key])):
                            return False
                    except:
                        return False
                elif op == '$gte':
                    if key not in doc or doc[key] < target_val:
                        return False
                elif op == '$lte':
                    if key not in doc or doc[key] > target_val:
                        return False
                elif op == '$in':
                    if key not in doc or doc[key] not in target_val:
                        return False
                continue
            
            # Standard exact match
            if key == '_id':
                if str(doc.get('_id', '')) != str(val) and str(doc.get('id', '')) != str(val):
                    return False
            else:
                if str(doc.get(key, '')).lower() != str(val).lower():
                    return False
        return True

    def find(self, filter={}, sort=None, limit=0, skip=0):
        docs = self._read()
        filtered = [d for d in docs if self._matches_filter(d, filter)]
        
        # Apply sorting
        if sort:
            field, direction = sort[0]
            reverse = direction == -1
            filtered.sort(key=lambda d: d.get(field, ''), reverse=reverse)
            
        if skip:
            filtered = filtered[skip:]
        if limit:
            filtered = filtered[:limit]
            
        return filtered

    def find_one(self, filter={}):
        docs = self._read()
        for d in docs:
            if self._matches_filter(d, filter):
                return d
        return None

    def insert_one(self, document):
        docs = self._read()
        if '_id' not in document:
            document['_id'] = str(uuid.uuid4())
        
        # Convert date objects
        for k, v in document.items():
            if isinstance(v, (datetime.datetime, datetime.date)):
                document[k] = v.isoformat()
                
        docs.append(document)
        self._write(docs)
        
        class MockInsertResult:
            def __init__(self, inserted_id):
                self.inserted_id = inserted_id
        return MockInsertResult(document['_id'])

    def update_one(self, filter, update):
        docs = self._read()
        matched_idx = -1
        for i, d in enumerate(docs):
            if self._matches_filter(d, filter):
                matched_idx = i
                break
        
        if matched_idx == -1:
            class MockUpdateResult:
                modified_count = 0
            return MockUpdateResult()
            
        doc = docs[matched_idx]
        
        # Support $set
        set_data = update.get('$set', update)
        for k, v in set_data.items():
            if isinstance(v, (datetime.datetime, datetime.date)):
                v = v.isoformat()
            doc[k] = v
            
        doc['updated_at'] = datetime.datetime.utcnow().isoformat()
        docs[matched_idx] = doc
        self._write(docs)
        
        class MockUpdateResult:
            modified_count = 1
        return MockUpdateResult()

    def delete_one(self, filter):
        docs = self._read()
        matched_idx = -1
        for i, d in enumerate(docs):
            if self._matches_filter(d, filter):
                matched_idx = i
                break
        if matched_idx != -1:
            del docs[matched_idx]
            self._write(docs)
            class MockDeleteResult:
                deleted_count = 1
            return MockDeleteResult()
            
        class MockDeleteResult:
            deleted_count = 0
        return MockDeleteResult()

    def delete_many(self, filter={}):
        docs = self._read()
        before_count = len(docs)
        remaining = [d for d in docs if not self._matches_filter(d, filter)]
        self._write(remaining)
        
        class MockDeleteResult:
            deleted_count = before_count - len(remaining)
        return MockDeleteResult()

    def count_documents(self, filter={}):
        docs = self._read()
        return len([d for d in docs if self._matches_filter(d, filter)])

class FallbackMongoClient:
    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.users = FallbackCollection('users', data_dir)
        self.logs = FallbackCollection('logs', data_dir)
        self.alerts = FallbackCollection('alerts', data_dir)
        self.incidents = FallbackCollection('incidents', data_dir)
        self.audit_logs = FallbackCollection('audit_logs', data_dir)

# Initialize Database Client
db = None
db_mode = None

try:
    print(f"[*] Attempting to connect to MongoDB: {MONGODB_URI}")
    # Short server selection timeout (3 seconds) to fail-fast
    client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=3000)
    client.server_info() # Forces connection check
    
    db = client[DB_NAME]
    db_mode = 'MongoDB Direct'
    print("[+] MongoDB Connected Successfully!")
except (ConnectionFailure, ServerSelectionTimeoutError) as e:
    print(f"[-] MongoDB Connection Failed: {e}")
    print(f"[!] SWITCHING TO LOCAL JSON FALLBACK MODE (Writing files to backend/data/)")
    db = FallbackMongoClient(FALLBACK_DATA_DIR)
    db_mode = 'JSON Fallback'

def get_db():
    return db

def get_db_mode():
    return db_mode
