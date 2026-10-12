# import os

# # Quieter, lighter TensorFlow (must be set before importing tensorflow)
# os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
# os.environ.setdefault("TF_ENABLE_ONEDNN_OPTS", "0")

# import re
# import time
# import pickle
# import threading
# from enum import Enum
# from functools import lru_cache

# import joblib
# import numpy as np
# import pandas as pd
# import tensorflow as tf
# from fastapi import FastAPI, UploadFile, File, Form, HTTPException
# from fastapi.middleware.cors import CORSMiddleware
# from huggingface_hub import hf_hub_download
# from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
# from sklearn.metrics.pairwise import cosine_similarity

# BASE_DIR = os.getenv("MODEL_DIR") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "saved_models")
# HF_REPO = os.getenv("HF_REPO", "Rithvik-3103/cyber-ann-models")
# HF_REPO_TYPE = os.getenv("HF_REPO_TYPE", "model")  # your repo is a public MODEL repo
# HF_TOKEN = (os.getenv("HF_TOKEN") or "").strip() or None  # leave unset for public repos
# MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "30"))
# MAX_THREAT_ROWS = int(os.getenv("MAX_THREAT_ROWS", "5000"))
# MAX_ROWS = int(os.getenv("MAX_ROWS", "100000"))                  # /predict row limit
# COMPARE_MAX_ROWS = int(os.getenv("COMPARE_MAX_ROWS", "30000"))   # /compare row limit (8 models)
# CHUNK_ROWS = int(os.getenv("CHUNK_ROWS", "20000"))               # rows processed at a time
# SEVERITY_BANDS = ((0.90, "high"), (0.70, "medium"))

# os.makedirs(BASE_DIR, exist_ok=True)

# # One heavy job at a time: protects a small instance from running out of RAM
# SCAN_LOCK = threading.Lock()


# # ==========================================
# # LAZY ARTIFACT DOWNLOAD (Hugging Face)
# # Files are fetched the first time they are needed, so the server
# # starts instantly and Render's port check passes.
# # ==========================================
# def ensure_file(filename):
#     path = os.path.join(BASE_DIR, filename)
#     if not os.path.exists(path):
#         print(f"Downloading {filename} from Hugging Face...", flush=True)
#         hf_hub_download(
#             repo_id=HF_REPO,
#             repo_type=HF_REPO_TYPE,
#             filename=filename,
#             local_dir=BASE_DIR,
#             token=HF_TOKEN,
#         )
#     return path


# app = FastAPI(title="AI-SIEM Multi-Dataset Intrusion Detection API")

# origins = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",") if o.strip()]
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=origins,
#     allow_credentials=False,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )


# class DatasetEnum(str, Enum):
#     nsl_kdd = "nsl_kdd"
#     cicids2017 = "cicids2017"
#     unsw_nb15 = "unsw_nb15"


# class ModelEnum(str, Enum):
#     svm = "svm"
#     knn = "knn"
#     random_forest = "random_forest"
#     naive_bayes = "naive_bayes"
#     decision_tree = "decision_tree"
#     fcnn = "fcnn"
#     cnn = "cnn"
#     lstm = "lstm"


# def sanitize(name):
#     return re.sub(r"[^0-9a-zA-Z]+", "_", str(name).strip()).strip("_").lower()


# class EventEncoder:
#     def __init__(self, n_bins=10):
#         self.n_bins = n_bins
#         self.num_cols, self.cat_cols, self.edges = [], [], {}

#     def transform(self, df):
#         cols = []
#         for c in self.num_cols:
#             e = self.edges[c]
#             idx = np.searchsorted(e, df[c].to_numpy(dtype=np.float64), side="left")
#             lut = np.array([f"{sanitize(c)}_b{i}" for i in range(len(e) + 1)], dtype=object)
#             cols.append(lut[idx])
#         for c in self.cat_cols:
#             s = df[c].astype(str).str.strip().str.lower().str.replace(r"\s+", "_", regex=True)
#             cols.append((sanitize(c) + "_" + s).to_numpy(dtype=object))
#         mat = np.column_stack(cols)
#         return [" ".join(row) for row in mat]

#     def load_state(self, state_dict):
#         self.n_bins = state_dict["n_bins"]
#         self.num_cols = state_dict["num_cols"]
#         self.cat_cols = state_dict["cat_cols"]
#         self.edges = state_dict["edges"]
#         return self


# def clean_dataframe(df):
#     d = df.replace([np.inf, -np.inf], np.nan)
#     for c in d.select_dtypes(include=[np.number]).columns:
#         if d[c].isna().any():
#             d[c] = d[c].fillna(d[c].median())
#     for c in [c for c in d.columns if not pd.api.types.is_numeric_dtype(d[c])]:
#         if d[c].isna().any():
#             mode_val = d[c].mode()
#             d[c] = d[c].fillna(mode_val.iloc[0] if not mode_val.empty else "unknown")
#     return d


# def to_sequence(X, steps=32):
#     n, f = X.shape
#     pad = (-f) % steps
#     if pad:
#         X = np.hstack([X, np.zeros((n, pad), dtype=X.dtype)])
#     return X.reshape(n, steps, -1)


# @lru_cache(maxsize=3)
# def load_artifacts(prefix):
#     def _load(suffix):
#         with open(ensure_file(f"{prefix}_{suffix}.pkl"), "rb") as f:
#             return pickle.load(f)

#     enc = EventEncoder().load_state(_load("event_encoder"))
#     vec = _load("vectorizer")
#     basepoint = _load("basepoint")
#     scaler = _load("scaler")
#     meta = _load("meta")

#     try:
#         feature_names = np.asarray(vec.get_feature_names_out())
#     except Exception:
#         feature_names = None

#     bp = basepoint.toarray() if hasattr(basepoint, "toarray") else basepoint
#     bp_vec = np.asarray(bp, dtype=np.float64).reshape(-1)

#     return {
#         "enc": enc, "vec": vec, "basepoint": basepoint, "scaler": scaler,
#         "meta": meta, "feature_names": feature_names, "bp_vec": bp_vec,
#     }


# # Small caches keep memory low on small instances
# @lru_cache(maxsize=2)
# def load_dl_model(filename):
#     return tf.keras.models.load_model(ensure_file(filename), compile=False)


# @lru_cache(maxsize=3)
# def load_ml_model(filename):
#     return joblib.load(ensure_file(filename))


# def preprocess(df, art):
#     ev_data = art["enc"].transform(df)
#     X_vec = art["vec"].transform(ev_data)
#     sim = cosine_similarity(X_vec, art["basepoint"]).astype(np.float32)
#     X_dense = X_vec.toarray()
#     X_p = np.hstack([X_dense, sim])
#     X_s = art["scaler"].transform(X_p).astype(np.float32)
#     np.clip(X_s, -art["meta"]["clip"], art["meta"]["clip"], out=X_s)
#     return X_s, X_dense, sim.max(axis=1)


# class InputError(ValueError):
#     pass


# def required_columns(art):
#     return [str(c) for c in (*art["enc"].num_cols, *art["enc"].cat_cols)]


# def check_required_columns(df, art, prefix):
#     required = required_columns(art)
#     present = {str(c) for c in df.columns}
#     missing = [c for c in required if c not in present]
#     if missing:
#         shown = ", ".join(repr(c) for c in missing[:10])
#         more = f" (and {len(missing) - 10} more)" if len(missing) > 10 else ""
#         raise InputError(
#             f"Your CSV is missing {len(missing)} of the {len(required)} columns the {prefix} "
#             f"model needs: {shown}{more}. Check that you picked the right dataset."
#         )


# def read_and_prepare(file, prefix, max_rows=None):
#     max_rows = max_rows or MAX_ROWS
#     # Enforce the upload limit on the server too
#     file.file.seek(0, os.SEEK_END)
#     size = file.file.tell()
#     file.file.seek(0)
#     if size > MAX_UPLOAD_MB * 1024 * 1024:
#         raise InputError(f"File is {size / 1024 / 1024:.1f} MB. The server limit is {MAX_UPLOAD_MB} MB.")

#     try:
#         raw = pd.read_csv(file.file, nrows=max_rows + 1)  # stop reading early if the file is too long
#     except Exception as e:
#         raise InputError(f"Could not read the file as a CSV: {e}")
#     if raw.empty:
#         raise InputError("The uploaded CSV has no rows.")
#     if len(raw) > max_rows:
#         raise InputError(
#             f"This CSV has more than {max_rows:,} rows, which is the limit for this server. "
#             "Upload a smaller sample or split the file."
#         )

#     # Keep the label column out of cleaning so unlabelled rows stay unlabelled
#     label_col = next((c for c in raw.columns if str(c).strip().lower() == "label"), None)
#     labels = raw[label_col].copy() if label_col is not None else None
#     features = raw.drop(columns=[label_col]) if label_col is not None else raw

#     df = clean_dataframe(features)
#     art = load_artifacts(prefix)
#     check_required_columns(df, art, prefix)

#     df_original = df.copy()
#     if labels is not None:
#         df_original[label_col] = labels.to_numpy()
#     return df_original, df, art


# def predict_fcnn(model, X_s, dataset_name):
#     probs = model.predict(X_s, batch_size=1024, verbose=0).ravel()
#     if dataset_name == "cicids2017":
#         scores = np.power(probs, 0.65)
#         predictions = (scores >= 0.01).astype(int)
#     else:
#         scores = probs
#         predictions = (probs >= 0.5).astype(int)
#     return predictions, scores


# def predict_cnn_lstm(model, X_s, model_type, meta):
#     if model_type == "cnn":
#         X_input = X_s[..., np.newaxis]
#     elif model_type == "lstm":
#         X_input = to_sequence(X_s, steps=meta.get("lstm_steps", 32))
#     else:
#         X_input = X_s

#     probs = model.predict(X_input, batch_size=1024, verbose=0).ravel()
#     return (probs >= 0.5).astype(int), probs


# def predict_ml_model(model, X_s, want_scores=True):
#     predictions = np.asarray(model.predict(X_s)).astype(int)
#     scores = None

#     if want_scores and hasattr(model, "predict_proba"):
#         try:
#             proba = model.predict_proba(X_s)
#             classes = list(getattr(model, "classes_", [0, 1]))
#             col = classes.index(1) if 1 in classes else proba.shape[1] - 1
#             scores = proba[:, col]
#         except Exception:
#             scores = None

#     if want_scores and scores is None and hasattr(model, "decision_function"):
#         try:
#             d = np.asarray(model.decision_function(X_s)).ravel()
#             scores = 1.0 / (1.0 + np.exp(-np.clip(d, -30, 30)))
#         except Exception:
#             scores = None

#     if scores is None:
#         scores = predictions.astype(float)
#     return predictions, scores


# def run_model(prefix, model_name, X_s, meta, want_scores=True):
#     if model_name == "fcnn":
#         model = load_dl_model(f"{prefix}_dl_fcnn.keras")
#         return predict_fcnn(model, X_s, prefix)
#     if model_name in ("cnn", "lstm"):
#         model = load_dl_model(f"{prefix}_dl_{model_name}.keras")
#         return predict_cnn_lstm(model, X_s, model_name, meta)
#     model = load_ml_model(f"{prefix}_ml_{model_name}.pkl")
#     return predict_ml_model(model, X_s, want_scores)


# def top_events(X_dense_rows, art, top_k=3):
#     names, bp = art["feature_names"], art["bp_vec"]
#     if names is None or bp.shape[0] != X_dense_rows.shape[1]:
#         return [[] for _ in range(len(X_dense_rows))]
#     delta = X_dense_rows - bp
#     top = np.argsort(-delta, axis=1)[:, :top_k]
#     return [[str(names[c]) for c in cols if delta[r, c] > 0] for r, cols in enumerate(top)]


# def scan_in_chunks(df, art, prefix, model_name):
#     """Preprocess + predict a slice at a time so memory stays small on big files."""
#     n = len(df)
#     preds = np.zeros(n, dtype=int)
#     scores = np.zeros(n, dtype=np.float64)
#     sims = np.zeros(n, dtype=np.float32)
#     events = {}
#     for s in range(0, n, CHUNK_ROWS):
#         e = min(n, s + CHUNK_ROWS)
#         X_s, X_dense, sim = preprocess(df.iloc[s:e], art)
#         p, sc = run_model(prefix, model_name, X_s, art["meta"])
#         p = np.asarray(p).astype(int)
#         sc = np.nan_to_num(np.asarray(sc, dtype=np.float64))
#         preds[s:e], scores[s:e], sims[s:e] = p, sc, sim
#         hit = np.flatnonzero(p == 1)
#         if len(hit):
#             for i, ev in zip(hit, top_events(X_dense[hit], art)):
#                 events[s + int(i)] = ev
#         print(f"[{prefix}/{model_name}] processed {e:,}/{n:,} rows", flush=True)
#     return preds, scores, sims, events


# def severity_of(score):
#     for limit, name in SEVERITY_BANDS:
#         if score >= limit:
#             return name
#     return "low"


# def severity_counts(scores):
#     counts = {name: 0 for _, name in SEVERITY_BANDS}
#     remaining = np.ones(len(scores), dtype=bool)
#     for limit, name in SEVERITY_BANDS:
#         hit = remaining & (scores >= limit)
#         counts[name] = int(hit.sum())
#         remaining &= ~hit
#     counts["low"] = int(remaining.sum())
#     return counts


# def build_threat_meta(keep, scores, sim, events):
#     out = []
#     for i in keep:
#         score = float(scores[i])
#         out.append({
#             "row": int(i) + 1,
#             "score": round(score, 4),
#             "severity": severity_of(score),
#             "similarity_to_normal": round(float(sim[i]), 4),
#             "unusual_events": events.get(int(i), []),
#         })
#     return out


# NORMAL_LABELS = {"normal", "benign", "0", "0.0", "false", "none"}


# def compute_metrics(df_original, predictions):
#     try:
#         col = next((c for c in df_original.columns if str(c).strip().lower() == "label"), None)
#         if col is None:
#             return None
#         series = df_original[col]
#         mask = series.notna().to_numpy()
#         if mask.sum() == 0:
#             return None

#         labelled = series[mask]
#         if pd.api.types.is_numeric_dtype(labelled):
#             y_true = (labelled.astype(float) != 0).astype(int).to_numpy()
#         else:
#             y_true = (~labelled.astype(str).str.strip().str.lower().isin(NORMAL_LABELS)).astype(int).to_numpy()
#         y_pred = np.asarray(predictions).astype(int)[mask]

#         tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
#         return {
#             "label_column": str(col),
#             "labelled_records": int(mask.sum()),
#             "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
#             "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
#             "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
#             "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
#             "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
#         }
#     except Exception:
#         return None


# @app.get("/")
# def root():
#     return {"service": "AI-SIEM API", "docs": "/docs", "health": "/health"}


# @app.get("/health")
# def health():
#     return {"status": "ok"}


# @app.get("/schema/{dataset}")
# def schema(dataset: DatasetEnum):
#     try:
#         art = load_artifacts(dataset.value)
#         return {
#             "dataset": dataset.value,
#             "required_columns": required_columns(art),
#             "optional_columns": ["label"],
#         }
#     except FileNotFoundError:
#         raise HTTPException(status_code=404, detail=f"No saved artifacts found for {dataset.value}.")
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))


# # Plain "def" (not async): FastAPI runs these in a worker thread,
# # so /health keeps answering while a scan is running.
# @app.post("/predict")
# def predict(
#     dataset: DatasetEnum = Form(...),
#     model_type: ModelEnum = Form(...),
#     file: UploadFile = File(...),
# ):
#     try:
#         with SCAN_LOCK:
#             started = time.time()
#             prefix = dataset.value

#             df_original, df_feat, art = read_and_prepare(file, prefix)

#             predictions, scores, sim, events = scan_in_chunks(df_feat, art, prefix, model_type.value)

#             label_map = {0: "normal", 1: "attack"}
#             results = [label_map[p] for p in predictions.tolist()]

#             total_records = len(results)
#             threat_count = results.count("attack")
#             normal_count = total_records - threat_count

#             df_original["predicted_status"] = results

#             threat_idx = np.flatnonzero(predictions == 1)
#             keep = threat_idx
#             if MAX_THREAT_ROWS and len(threat_idx) > MAX_THREAT_ROWS:
#                 keep = np.sort(threat_idx[np.argsort(-scores[threat_idx])[:MAX_THREAT_ROWS]])

#             df_threats = df_original.iloc[keep].astype(object)
#             df_threats = df_threats.where(pd.notna(df_threats), None)
#             threat_details = df_threats.to_dict(orient="records")

#             threat_meta = build_threat_meta(keep, scores, sim, events)

#             return {
#                 "summary": {
#                     "total_records": total_records,
#                     "normal_traffic": normal_count,
#                     "detected_threats": threat_count,
#                     "severity_counts": severity_counts(scores[threat_idx]),
#                     "threats_returned": len(threat_details),
#                     "threats_truncated": len(threat_details) < threat_count,
#                     "dataset": prefix,
#                     "model_type": model_type.value,
#                     "elapsed_seconds": round(time.time() - started, 2),
#                 },
#                 "threat_details": threat_details,
#                 "threat_meta": threat_meta,
#                 "metrics": compute_metrics(df_original, predictions),
#             }

#     except InputError as e:
#         raise HTTPException(status_code=422, detail=str(e))
#     except HTTPException:
#         raise
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))


# @app.post("/compare")
# def compare(
#     dataset: DatasetEnum = Form(...),
#     file: UploadFile = File(...),
# ):
#     try:
#         with SCAN_LOCK:
#             prefix = dataset.value
#             df_original, df_feat, art = read_and_prepare(file, prefix, COMPARE_MAX_ROWS)
#             X_s = np.vstack([
#                 preprocess(df_feat.iloc[a:a + CHUNK_ROWS], art)[0]
#                 for a in range(0, len(df_feat), CHUNK_ROWS)
#             ])
#             total = len(df_original)

#             rows, preds_by_model = [], {}
#             for m in ModelEnum:
#                 started = time.time()
#                 try:
#                     preds, _ = run_model(prefix, m.value, X_s, art["meta"], want_scores=False)
#                     preds = np.asarray(preds).astype(int)
#                     preds_by_model[m.value] = preds

#                     threats = int(preds.sum())
#                     row = {
#                         "model": m.value,
#                         "status": "ok",
#                         "threats": threats,
#                         "normal": total - threats,
#                         "threat_rate": round(100.0 * threats / total, 2),
#                         "seconds": round(time.time() - started, 2),
#                     }
#                     metrics = compute_metrics(df_original, preds)
#                     if metrics:
#                         row["metrics"] = metrics
#                 except Exception as e:
#                     row = {"model": m.value, "status": "error", "detail": str(e)}
#                 rows.append(row)

#             agreement = None
#             ok = len(preds_by_model)
#             if ok >= 2:
#                 votes = np.sum(list(preds_by_model.values()), axis=0)
#                 majority = (votes * 2 > ok).astype(int)
#                 agreement = {
#                     "models_compared": ok,
#                     "unanimous_threat": int((votes == ok).sum()),
#                     "unanimous_normal": int((votes == 0).sum()),
#                     "split": int(((votes > 0) & (votes < ok)).sum()),
#                 }
#                 for row in rows:
#                     if row["status"] == "ok":
#                         same = preds_by_model[row["model"]] == majority
#                         row["agrees_with_majority"] = round(100.0 * float(same.mean()), 2)

#             return {"dataset": prefix, "total_records": total, "models": rows, "agreement": agreement}

#     except InputError as e:
#         raise HTTPException(status_code=422, detail=str(e))
#     except HTTPException:
#         raise
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))


# ####V211
# import os

# # Quieter, lighter TensorFlow (must be set before importing tensorflow)
# os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
# os.environ.setdefault("TF_ENABLE_ONEDNN_OPTS", "0")

# import re
# import json
# import time
# import pickle
# import threading
# from enum import Enum
# from functools import lru_cache

# import joblib
# import numpy as np
# import pandas as pd
# import tensorflow as tf
# from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Response
# from fastapi.middleware.cors import CORSMiddleware
# from huggingface_hub import hf_hub_download
# from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
# from sklearn.metrics.pairwise import cosine_similarity

# BASE_DIR = os.getenv("MODEL_DIR") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "saved_models")
# HF_REPO = os.getenv("HF_REPO", "Rithvik-3103/cyber-ann-models")
# HF_REPO_TYPE = os.getenv("HF_REPO_TYPE", "model")  # your repo is a public MODEL repo
# HF_TOKEN = (os.getenv("HF_TOKEN") or "").strip() or None  # leave unset for public repos
# MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "30"))
# MAX_THREAT_ROWS = int(os.getenv("MAX_THREAT_ROWS", "2000"))
# MAX_ROWS = int(os.getenv("MAX_ROWS", "100000"))                  # /predict row limit
# COMPARE_MAX_ROWS = int(os.getenv("COMPARE_MAX_ROWS", "30000"))   # /compare row limit (8 models)
# CHUNK_ROWS = int(os.getenv("CHUNK_ROWS", "20000"))               # rows processed at a time
# SEVERITY_BANDS = ((0.90, "high"), (0.70, "medium"))

# os.makedirs(BASE_DIR, exist_ok=True)

# # One heavy job at a time: protects a small instance from running out of RAM
# SCAN_LOCK = threading.Lock()


# # ==========================================
# # LAZY ARTIFACT DOWNLOAD (Hugging Face)
# # Files are fetched the first time they are needed, so the server
# # starts instantly and Render's port check passes.
# # ==========================================
# def ensure_file(filename):
#     path = os.path.join(BASE_DIR, filename)
#     if not os.path.exists(path):
#         print(f"Downloading {filename} from Hugging Face...", flush=True)
#         hf_hub_download(
#             repo_id=HF_REPO,
#             repo_type=HF_REPO_TYPE,
#             filename=filename,
#             local_dir=BASE_DIR,
#             token=HF_TOKEN,
#         )
#     return path


# app = FastAPI(title="AI-SIEM Multi-Dataset Intrusion Detection API")

# origins = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",") if o.strip()]
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=origins,
#     allow_credentials=False,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )


# class DatasetEnum(str, Enum):
#     nsl_kdd = "nsl_kdd"
#     cicids2017 = "cicids2017"
#     unsw_nb15 = "unsw_nb15"


# class ModelEnum(str, Enum):
#     svm = "svm"
#     knn = "knn"
#     random_forest = "random_forest"
#     naive_bayes = "naive_bayes"
#     decision_tree = "decision_tree"
#     fcnn = "fcnn"
#     cnn = "cnn"
#     lstm = "lstm"


# def sanitize(name):
#     return re.sub(r"[^0-9a-zA-Z]+", "_", str(name).strip()).strip("_").lower()


# class EventEncoder:
#     def __init__(self, n_bins=10):
#         self.n_bins = n_bins
#         self.num_cols, self.cat_cols, self.edges = [], [], {}

#     def transform(self, df):
#         cols = []
#         for c in self.num_cols:
#             e = self.edges[c]
#             idx = np.searchsorted(e, df[c].to_numpy(dtype=np.float64), side="left")
#             lut = np.array([f"{sanitize(c)}_b{i}" for i in range(len(e) + 1)], dtype=object)
#             cols.append(lut[idx])
#         for c in self.cat_cols:
#             s = df[c].astype(str).str.strip().str.lower().str.replace(r"\s+", "_", regex=True)
#             cols.append((sanitize(c) + "_" + s).to_numpy(dtype=object))
#         mat = np.column_stack(cols)
#         return [" ".join(row) for row in mat]

#     def load_state(self, state_dict):
#         self.n_bins = state_dict["n_bins"]
#         self.num_cols = state_dict["num_cols"]
#         self.cat_cols = state_dict["cat_cols"]
#         self.edges = state_dict["edges"]
#         return self


# def clean_dataframe(df):
#     d = df.replace([np.inf, -np.inf], np.nan)
#     for c in d.select_dtypes(include=[np.number]).columns:
#         if d[c].isna().any():
#             d[c] = d[c].fillna(d[c].median())
#     for c in [c for c in d.columns if not pd.api.types.is_numeric_dtype(d[c])]:
#         if d[c].isna().any():
#             mode_val = d[c].mode()
#             d[c] = d[c].fillna(mode_val.iloc[0] if not mode_val.empty else "unknown")
#     return d


# def to_sequence(X, steps=32):
#     n, f = X.shape
#     pad = (-f) % steps
#     if pad:
#         X = np.hstack([X, np.zeros((n, pad), dtype=X.dtype)])
#     return X.reshape(n, steps, -1)


# @lru_cache(maxsize=3)
# def load_artifacts(prefix):
#     def _load(suffix):
#         with open(ensure_file(f"{prefix}_{suffix}.pkl"), "rb") as f:
#             return pickle.load(f)

#     enc = EventEncoder().load_state(_load("event_encoder"))
#     vec = _load("vectorizer")
#     basepoint = _load("basepoint")
#     scaler = _load("scaler")
#     meta = _load("meta")

#     try:
#         feature_names = np.asarray(vec.get_feature_names_out())
#     except Exception:
#         feature_names = None

#     bp = basepoint.toarray() if hasattr(basepoint, "toarray") else basepoint
#     bp_vec = np.asarray(bp, dtype=np.float64).reshape(-1)

#     return {
#         "enc": enc, "vec": vec, "basepoint": basepoint, "scaler": scaler,
#         "meta": meta, "feature_names": feature_names, "bp_vec": bp_vec,
#     }


# # Small caches keep memory low on small instances
# @lru_cache(maxsize=2)
# def load_dl_model(filename):
#     return tf.keras.models.load_model(ensure_file(filename), compile=False)


# @lru_cache(maxsize=3)
# def load_ml_model(filename):
#     return joblib.load(ensure_file(filename))


# def preprocess(df, art):
#     ev_data = art["enc"].transform(df)
#     X_vec = art["vec"].transform(ev_data)
#     sim = cosine_similarity(X_vec, art["basepoint"]).astype(np.float32)
#     X_dense = X_vec.toarray()
#     X_p = np.hstack([X_dense, sim])
#     X_s = art["scaler"].transform(X_p).astype(np.float32)
#     np.clip(X_s, -art["meta"]["clip"], art["meta"]["clip"], out=X_s)
#     return X_s, X_dense, sim.max(axis=1)


# class InputError(ValueError):
#     pass


# def required_columns(art):
#     return [str(c) for c in (*art["enc"].num_cols, *art["enc"].cat_cols)]


# def check_required_columns(df, art, prefix):
#     required = required_columns(art)
#     present = {str(c) for c in df.columns}
#     missing = [c for c in required if c not in present]
#     if missing:
#         shown = ", ".join(repr(c) for c in missing[:10])
#         more = f" (and {len(missing) - 10} more)" if len(missing) > 10 else ""
#         raise InputError(
#             f"Your CSV is missing {len(missing)} of the {len(required)} columns the {prefix} "
#             f"model needs: {shown}{more}. Check that you picked the right dataset."
#         )


# def read_and_prepare(file, prefix, max_rows=None):
#     max_rows = max_rows or MAX_ROWS
#     # Enforce the upload limit on the server too
#     file.file.seek(0, os.SEEK_END)
#     size = file.file.tell()
#     file.file.seek(0)
#     if size > MAX_UPLOAD_MB * 1024 * 1024:
#         raise InputError(f"File is {size / 1024 / 1024:.1f} MB. The server limit is {MAX_UPLOAD_MB} MB.")

#     try:
#         raw = pd.read_csv(file.file, nrows=max_rows + 1)  # stop reading early if the file is too long
#     except Exception as e:
#         raise InputError(f"Could not read the file as a CSV: {e}")
#     if raw.empty:
#         raise InputError("The uploaded CSV has no rows.")
#     if len(raw) > max_rows:
#         raise InputError(
#             f"This CSV has more than {max_rows:,} rows, which is the limit for this server. "
#             "Upload a smaller sample or split the file."
#         )

#     # Keep the label column out of cleaning so unlabelled rows stay unlabelled
#     label_col = next((c for c in raw.columns if str(c).strip().lower() == "label"), None)
#     labels = raw[label_col].copy() if label_col is not None else None
#     features = raw.drop(columns=[label_col]) if label_col is not None else raw

#     df = clean_dataframe(features)
#     art = load_artifacts(prefix)
#     check_required_columns(df, art, prefix)

#     df_original = df.copy()
#     if labels is not None:
#         df_original[label_col] = labels.to_numpy()
#     return df_original, df, art


# def predict_fcnn(model, X_s, dataset_name):
#     probs = model.predict(X_s, batch_size=1024, verbose=0).ravel()
#     if dataset_name == "cicids2017":
#         scores = np.power(probs, 0.65)
#         predictions = (scores >= 0.01).astype(int)
#     else:
#         scores = probs
#         predictions = (probs >= 0.5).astype(int)
#     return predictions, scores


# def predict_cnn_lstm(model, X_s, model_type, meta):
#     if model_type == "cnn":
#         X_input = X_s[..., np.newaxis]
#     elif model_type == "lstm":
#         X_input = to_sequence(X_s, steps=meta.get("lstm_steps", 32))
#     else:
#         X_input = X_s

#     probs = model.predict(X_input, batch_size=1024, verbose=0).ravel()
#     return (probs >= 0.5).astype(int), probs


# def predict_ml_model(model, X_s, want_scores=True):
#     predictions = np.asarray(model.predict(X_s)).astype(int)
#     scores = None

#     if want_scores and hasattr(model, "predict_proba"):
#         try:
#             proba = model.predict_proba(X_s)
#             classes = list(getattr(model, "classes_", [0, 1]))
#             col = classes.index(1) if 1 in classes else proba.shape[1] - 1
#             scores = proba[:, col]
#         except Exception:
#             scores = None

#     if want_scores and scores is None and hasattr(model, "decision_function"):
#         try:
#             d = np.asarray(model.decision_function(X_s)).ravel()
#             scores = 1.0 / (1.0 + np.exp(-np.clip(d, -30, 30)))
#         except Exception:
#             scores = None

#     if scores is None:
#         scores = predictions.astype(float)
#     return predictions, scores


# def run_model(prefix, model_name, X_s, meta, want_scores=True):
#     if model_name == "fcnn":
#         model = load_dl_model(f"{prefix}_dl_fcnn.keras")
#         return predict_fcnn(model, X_s, prefix)
#     if model_name in ("cnn", "lstm"):
#         model = load_dl_model(f"{prefix}_dl_{model_name}.keras")
#         return predict_cnn_lstm(model, X_s, model_name, meta)
#     model = load_ml_model(f"{prefix}_ml_{model_name}.pkl")
#     return predict_ml_model(model, X_s, want_scores)


# def top_events(X_dense_rows, art, top_k=3):
#     names, bp = art["feature_names"], art["bp_vec"]
#     if names is None or bp.shape[0] != X_dense_rows.shape[1]:
#         return [[] for _ in range(len(X_dense_rows))]
#     delta = X_dense_rows - bp
#     top = np.argsort(-delta, axis=1)[:, :top_k]
#     return [[str(names[c]) for c in cols if delta[r, c] > 0] for r, cols in enumerate(top)]


# def scan_in_chunks(df, art, prefix, model_name):
#     """Preprocess + predict a slice at a time so memory stays small on big files."""
#     n = len(df)
#     preds = np.zeros(n, dtype=int)
#     scores = np.zeros(n, dtype=np.float64)
#     sims = np.zeros(n, dtype=np.float32)
#     events = {}
#     for s in range(0, n, CHUNK_ROWS):
#         e = min(n, s + CHUNK_ROWS)
#         X_s, X_dense, sim = preprocess(df.iloc[s:e], art)
#         p, sc = run_model(prefix, model_name, X_s, art["meta"])
#         p = np.asarray(p).astype(int)
#         sc = np.nan_to_num(np.asarray(sc, dtype=np.float64))
#         preds[s:e], scores[s:e], sims[s:e] = p, sc, sim
#         hit = np.flatnonzero(p == 1)
#         if len(hit):
#             for i, ev in zip(hit, top_events(X_dense[hit], art)):
#                 events[s + int(i)] = ev
#         print(f"[{prefix}/{model_name}] processed {e:,}/{n:,} rows", flush=True)
#     return preds, scores, sims, events


# def severity_of(score):
#     for limit, name in SEVERITY_BANDS:
#         if score >= limit:
#             return name
#     return "low"


# def severity_counts(scores):
#     counts = {name: 0 for _, name in SEVERITY_BANDS}
#     remaining = np.ones(len(scores), dtype=bool)
#     for limit, name in SEVERITY_BANDS:
#         hit = remaining & (scores >= limit)
#         counts[name] = int(hit.sum())
#         remaining &= ~hit
#     counts["low"] = int(remaining.sum())
#     return counts


# def build_threat_meta(keep, scores, sim, events):
#     out = []
#     for i in keep:
#         score = float(scores[i])
#         out.append({
#             "row": int(i) + 1,
#             "score": round(score, 4),
#             "severity": severity_of(score),
#             "similarity_to_normal": round(float(sim[i]), 4),
#             "unusual_events": events.get(int(i), []),
#         })
#     return out


# NORMAL_LABELS = {"normal", "benign", "0", "0.0", "false", "none"}


# def compute_metrics(df_original, predictions):
#     try:
#         col = next((c for c in df_original.columns if str(c).strip().lower() == "label"), None)
#         if col is None:
#             return None
#         series = df_original[col]
#         mask = series.notna().to_numpy()
#         if mask.sum() == 0:
#             return None

#         labelled = series[mask]
#         if pd.api.types.is_numeric_dtype(labelled):
#             y_true = (labelled.astype(float) != 0).astype(int).to_numpy()
#         else:
#             y_true = (~labelled.astype(str).str.strip().str.lower().isin(NORMAL_LABELS)).astype(int).to_numpy()
#         y_pred = np.asarray(predictions).astype(int)[mask]

#         tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
#         return {
#             "label_column": str(col),
#             "labelled_records": int(mask.sum()),
#             "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
#             "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
#             "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
#             "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
#             "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
#         }
#     except Exception:
#         return None


# def _json_default(o):
#     if hasattr(o, "item"):          # numpy scalars
#         return o.item()
#     return str(o)


# def make_response(result, label):
#     """Serialize once, log the size, and send plain JSON (faster than FastAPI's encoder)."""
#     t = time.time()
#     body = json.dumps(result, default=_json_default, allow_nan=False, separators=(",", ":"))
#     print(f"[{label}] response ready: {len(body) / 1e6:.1f} MB, serialized in {time.time() - t:.1f}s", flush=True)
#     return Response(content=body, media_type="application/json")


# @app.get("/")
# def root():
#     return {"service": "AI-SIEM API", "version": "3.0", "docs": "/docs", "health": "/health"}


# @app.get("/health")
# def health():
#     return {"status": "ok"}


# @app.get("/schema/{dataset}")
# def schema(dataset: DatasetEnum):
#     try:
#         art = load_artifacts(dataset.value)
#         return {
#             "dataset": dataset.value,
#             "required_columns": required_columns(art),
#             "optional_columns": ["label"],
#         }
#     except FileNotFoundError:
#         raise HTTPException(status_code=404, detail=f"No saved artifacts found for {dataset.value}.")
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))


# # Plain "def" (not async): FastAPI runs these in a worker thread,
# # so /health keeps answering while a scan is running.
# @app.post("/predict")
# def predict(
#     dataset: DatasetEnum = Form(...),
#     model_type: ModelEnum = Form(...),
#     file: UploadFile = File(...),
# ):
#     try:
#         with SCAN_LOCK:
#             started = time.time()
#             prefix = dataset.value

#             df_original, df_feat, art = read_and_prepare(file, prefix)

#             predictions, scores, sim, events = scan_in_chunks(df_feat, art, prefix, model_type.value)

#             label_map = {0: "normal", 1: "attack"}
#             results = [label_map[p] for p in predictions.tolist()]

#             total_records = len(results)
#             threat_count = results.count("attack")
#             normal_count = total_records - threat_count

#             df_original["predicted_status"] = results

#             threat_idx = np.flatnonzero(predictions == 1)
#             keep = threat_idx
#             if MAX_THREAT_ROWS and len(threat_idx) > MAX_THREAT_ROWS:
#                 keep = np.sort(threat_idx[np.argsort(-scores[threat_idx])[:MAX_THREAT_ROWS]])

#             df_threats = df_original.iloc[keep].astype(object)
#             df_threats = df_threats.where(pd.notna(df_threats), None)
#             threat_details = df_threats.to_dict(orient="records")

#             threat_meta = build_threat_meta(keep, scores, sim, events)

#             result = {
#                 "summary": {
#                     "total_records": total_records,
#                     "normal_traffic": normal_count,
#                     "detected_threats": threat_count,
#                     "severity_counts": severity_counts(scores[threat_idx]),
#                     "threats_returned": len(threat_details),
#                     "threats_truncated": len(threat_details) < threat_count,
#                     "dataset": prefix,
#                     "model_type": model_type.value,
#                     "elapsed_seconds": round(time.time() - started, 2),
#                 },
#                 "threat_details": threat_details,
#                 "threat_meta": threat_meta,
#                 "metrics": compute_metrics(df_original, predictions),
#             }
#             return make_response(result, "predict")

#     except InputError as e:
#         raise HTTPException(status_code=422, detail=str(e))
#     except HTTPException:
#         raise
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))


# @app.post("/compare")
# def compare(
#     dataset: DatasetEnum = Form(...),
#     file: UploadFile = File(...),
# ):
#     try:
#         with SCAN_LOCK:
#             prefix = dataset.value
#             df_original, df_feat, art = read_and_prepare(file, prefix, COMPARE_MAX_ROWS)
#             X_s = np.vstack([
#                 preprocess(df_feat.iloc[a:a + CHUNK_ROWS], art)[0]
#                 for a in range(0, len(df_feat), CHUNK_ROWS)
#             ])
#             total = len(df_original)

#             rows, preds_by_model = [], {}
#             for m in ModelEnum:
#                 started = time.time()
#                 try:
#                     preds, _ = run_model(prefix, m.value, X_s, art["meta"], want_scores=False)
#                     preds = np.asarray(preds).astype(int)
#                     preds_by_model[m.value] = preds

#                     threats = int(preds.sum())
#                     row = {
#                         "model": m.value,
#                         "status": "ok",
#                         "threats": threats,
#                         "normal": total - threats,
#                         "threat_rate": round(100.0 * threats / total, 2),
#                         "seconds": round(time.time() - started, 2),
#                     }
#                     metrics = compute_metrics(df_original, preds)
#                     if metrics:
#                         row["metrics"] = metrics
#                 except Exception as e:
#                     row = {"model": m.value, "status": "error", "detail": str(e)}
#                 rows.append(row)

#             agreement = None
#             ok = len(preds_by_model)
#             if ok >= 2:
#                 votes = np.sum(list(preds_by_model.values()), axis=0)
#                 majority = (votes * 2 > ok).astype(int)
#                 agreement = {
#                     "models_compared": ok,
#                     "unanimous_threat": int((votes == ok).sum()),
#                     "unanimous_normal": int((votes == 0).sum()),
#                     "split": int(((votes > 0) & (votes < ok)).sum()),
#                 }
#                 for row in rows:
#                     if row["status"] == "ok":
#                         same = preds_by_model[row["model"]] == majority
#                         row["agrees_with_majority"] = round(100.0 * float(same.mean()), 2)

#             return make_response(
#                 {"dataset": prefix, "total_records": total, "models": rows, "agreement": agreement}, "compare"
#             )

#     except InputError as e:
#         raise HTTPException(status_code=422, detail=str(e))
#     except HTTPException:
#         raise
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))

# ###V3####
# import os

# # Quieter, lighter TensorFlow (must be set before importing tensorflow)
# os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
# os.environ.setdefault("TF_ENABLE_ONEDNN_OPTS", "0")

# import re
# import json
# import time
# import pickle
# import threading
# from enum import Enum
# from functools import lru_cache

# import joblib
# import numpy as np
# import pandas as pd
# from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Response
# from fastapi.middleware.cors import CORSMiddleware
# from huggingface_hub import hf_hub_download
# from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
# from sklearn.metrics.pairwise import cosine_similarity

# BASE_DIR = os.getenv("MODEL_DIR") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "saved_models")
# HF_REPO = os.getenv("HF_REPO", "Rithvik-3103/cyber-ann-models")
# HF_REPO_TYPE = os.getenv("HF_REPO_TYPE", "model")  # your repo is a public MODEL repo
# HF_TOKEN = (os.getenv("HF_TOKEN") or "").strip() or None  # leave unset for public repos
# MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "30"))
# MAX_THREAT_ROWS = int(os.getenv("MAX_THREAT_ROWS", "2000"))
# MAX_ROWS = int(os.getenv("MAX_ROWS", "100000"))                  # /predict row limit
# COMPARE_MAX_ROWS = int(os.getenv("COMPARE_MAX_ROWS", "30000"))   # /compare row limit (8 models)
# CHUNK_ROWS = int(os.getenv("CHUNK_ROWS", "20000"))               # rows processed at a time
# SEVERITY_BANDS = ((0.90, "high"), (0.70, "medium"))

# os.makedirs(BASE_DIR, exist_ok=True)

# # One heavy job at a time: protects a small instance from running out of RAM
# SCAN_LOCK = threading.Lock()


# # ==========================================
# # LAZY ARTIFACT DOWNLOAD (Hugging Face)
# # Files are fetched the first time they are needed, so the server
# # starts instantly and Render's port check passes.
# # ==========================================
# def ensure_file(filename):
#     path = os.path.join(BASE_DIR, filename)
#     if not os.path.exists(path):
#         print(f"Downloading {filename} from Hugging Face...", flush=True)
#         hf_hub_download(
#             repo_id=HF_REPO,
#             repo_type=HF_REPO_TYPE,
#             filename=filename,
#             local_dir=BASE_DIR,
#             token=HF_TOKEN,
#         )
#     return path


# app = FastAPI(title="AI-SIEM Multi-Dataset Intrusion Detection API")

# origins = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",") if o.strip()]
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=origins,
#     allow_credentials=False,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )


# class DatasetEnum(str, Enum):
#     nsl_kdd = "nsl_kdd"
#     cicids2017 = "cicids2017"
#     unsw_nb15 = "unsw_nb15"


# class ModelEnum(str, Enum):
#     svm = "svm"
#     knn = "knn"
#     random_forest = "random_forest"
#     naive_bayes = "naive_bayes"
#     decision_tree = "decision_tree"
#     fcnn = "fcnn"
#     cnn = "cnn"
#     lstm = "lstm"


# def sanitize(name):
#     return re.sub(r"[^0-9a-zA-Z]+", "_", str(name).strip()).strip("_").lower()


# class EventEncoder:
#     def __init__(self, n_bins=10):
#         self.n_bins = n_bins
#         self.num_cols, self.cat_cols, self.edges = [], [], {}

#     def transform(self, df):
#         cols = []
#         for c in self.num_cols:
#             e = self.edges[c]
#             idx = np.searchsorted(e, df[c].to_numpy(dtype=np.float64), side="left")
#             lut = np.array([f"{sanitize(c)}_b{i}" for i in range(len(e) + 1)], dtype=object)
#             cols.append(lut[idx])
#         for c in self.cat_cols:
#             s = df[c].astype(str).str.strip().str.lower().str.replace(r"\s+", "_", regex=True)
#             cols.append((sanitize(c) + "_" + s).to_numpy(dtype=object))
#         mat = np.column_stack(cols)
#         return [" ".join(row) for row in mat]

#     def load_state(self, state_dict):
#         self.n_bins = state_dict["n_bins"]
#         self.num_cols = state_dict["num_cols"]
#         self.cat_cols = state_dict["cat_cols"]
#         self.edges = state_dict["edges"]
#         return self


# def clean_dataframe(df):
#     d = df.replace([np.inf, -np.inf], np.nan)
#     for c in d.select_dtypes(include=[np.number]).columns:
#         if d[c].isna().any():
#             d[c] = d[c].fillna(d[c].median())
#     for c in [c for c in d.columns if not pd.api.types.is_numeric_dtype(d[c])]:
#         if d[c].isna().any():
#             mode_val = d[c].mode()
#             d[c] = d[c].fillna(mode_val.iloc[0] if not mode_val.empty else "unknown")
#     return d


# def to_sequence(X, steps=32):
#     n, f = X.shape
#     pad = (-f) % steps
#     if pad:
#         X = np.hstack([X, np.zeros((n, pad), dtype=X.dtype)])
#     return X.reshape(n, steps, -1)


# @lru_cache(maxsize=3)
# def load_artifacts(prefix):
#     def _load(suffix):
#         with open(ensure_file(f"{prefix}_{suffix}.pkl"), "rb") as f:
#             return pickle.load(f)

#     enc = EventEncoder().load_state(_load("event_encoder"))
#     vec = _load("vectorizer")
#     basepoint = _load("basepoint")
#     scaler = _load("scaler")
#     meta = _load("meta")

#     try:
#         feature_names = np.asarray(vec.get_feature_names_out())
#     except Exception:
#         feature_names = None

#     bp = basepoint.toarray() if hasattr(basepoint, "toarray") else basepoint
#     bp_vec = np.asarray(bp, dtype=np.float64).reshape(-1)

#     return {
#         "enc": enc, "vec": vec, "basepoint": basepoint, "scaler": scaler,
#         "meta": meta, "feature_names": feature_names, "bp_vec": bp_vec,
#     }


# # Small caches keep memory low on small instances
# @lru_cache(maxsize=2)
# def load_dl_model(filename):
#     # TensorFlow is imported only when a deep-learning model is first used.
#     # This keeps idle memory low, so ML models and /health work on small instances.
#     import tensorflow as tf
#     return tf.keras.models.load_model(ensure_file(filename), compile=False)


# @lru_cache(maxsize=3)
# def load_ml_model(filename):
#     return joblib.load(ensure_file(filename))


# def preprocess(df, art):
#     ev_data = art["enc"].transform(df)
#     X_vec = art["vec"].transform(ev_data)
#     sim = cosine_similarity(X_vec, art["basepoint"]).astype(np.float32)
#     X_dense = X_vec.toarray()
#     X_p = np.hstack([X_dense, sim])
#     X_s = art["scaler"].transform(X_p).astype(np.float32)
#     np.clip(X_s, -art["meta"]["clip"], art["meta"]["clip"], out=X_s)
#     return X_s, X_dense, sim.max(axis=1)


# class InputError(ValueError):
#     pass


# def required_columns(art):
#     return [str(c) for c in (*art["enc"].num_cols, *art["enc"].cat_cols)]


# def check_required_columns(df, art, prefix):
#     required = required_columns(art)
#     present = {str(c) for c in df.columns}
#     missing = [c for c in required if c not in present]
#     if missing:
#         shown = ", ".join(repr(c) for c in missing[:10])
#         more = f" (and {len(missing) - 10} more)" if len(missing) > 10 else ""
#         raise InputError(
#             f"Your CSV is missing {len(missing)} of the {len(required)} columns the {prefix} "
#             f"model needs: {shown}{more}. Check that you picked the right dataset."
#         )


# def read_and_prepare(file, prefix, max_rows=None):
#     max_rows = max_rows or MAX_ROWS
#     # Enforce the upload limit on the server too
#     file.file.seek(0, os.SEEK_END)
#     size = file.file.tell()
#     file.file.seek(0)
#     if size > MAX_UPLOAD_MB * 1024 * 1024:
#         raise InputError(f"File is {size / 1024 / 1024:.1f} MB. The server limit is {MAX_UPLOAD_MB} MB.")

#     try:
#         raw = pd.read_csv(file.file, nrows=max_rows + 1)  # stop reading early if the file is too long
#     except Exception as e:
#         raise InputError(f"Could not read the file as a CSV: {e}")
#     if raw.empty:
#         raise InputError("The uploaded CSV has no rows.")
#     if len(raw) > max_rows:
#         raise InputError(
#             f"This CSV has more than {max_rows:,} rows, which is the limit for this server. "
#             "Upload a smaller sample or split the file."
#         )

#     # Keep the label column out of cleaning so unlabelled rows stay unlabelled
#     label_col = next((c for c in raw.columns if str(c).strip().lower() == "label"), None)
#     labels = raw[label_col].copy() if label_col is not None else None
#     features = raw.drop(columns=[label_col]) if label_col is not None else raw

#     df = clean_dataframe(features)
#     art = load_artifacts(prefix)
#     check_required_columns(df, art, prefix)

#     df_original = df.copy()
#     if labels is not None:
#         df_original[label_col] = labels.to_numpy()
#     return df_original, df, art


# def predict_fcnn(model, X_s, dataset_name):
#     probs = model.predict(X_s, batch_size=1024, verbose=0).ravel()
#     if dataset_name == "cicids2017":
#         scores = np.power(probs, 0.65)
#         predictions = (scores >= 0.01).astype(int)
#     else:
#         scores = probs
#         predictions = (probs >= 0.5).astype(int)
#     return predictions, scores


# def predict_cnn_lstm(model, X_s, model_type, meta):
#     if model_type == "cnn":
#         X_input = X_s[..., np.newaxis]
#     elif model_type == "lstm":
#         X_input = to_sequence(X_s, steps=meta.get("lstm_steps", 32))
#     else:
#         X_input = X_s

#     probs = model.predict(X_input, batch_size=1024, verbose=0).ravel()
#     return (probs >= 0.5).astype(int), probs


# def predict_ml_model(model, X_s, want_scores=True):
#     predictions = np.asarray(model.predict(X_s)).astype(int)
#     scores = None

#     if want_scores and hasattr(model, "predict_proba"):
#         try:
#             proba = model.predict_proba(X_s)
#             classes = list(getattr(model, "classes_", [0, 1]))
#             col = classes.index(1) if 1 in classes else proba.shape[1] - 1
#             scores = proba[:, col]
#         except Exception:
#             scores = None

#     if want_scores and scores is None and hasattr(model, "decision_function"):
#         try:
#             d = np.asarray(model.decision_function(X_s)).ravel()
#             scores = 1.0 / (1.0 + np.exp(-np.clip(d, -30, 30)))
#         except Exception:
#             scores = None

#     if scores is None:
#         scores = predictions.astype(float)
#     return predictions, scores


# def run_model(prefix, model_name, X_s, meta, want_scores=True):
#     if model_name == "fcnn":
#         model = load_dl_model(f"{prefix}_dl_fcnn.keras")
#         return predict_fcnn(model, X_s, prefix)
#     if model_name in ("cnn", "lstm"):
#         model = load_dl_model(f"{prefix}_dl_{model_name}.keras")
#         return predict_cnn_lstm(model, X_s, model_name, meta)
#     model = load_ml_model(f"{prefix}_ml_{model_name}.pkl")
#     return predict_ml_model(model, X_s, want_scores)


# def top_events(X_dense_rows, art, top_k=3):
#     names, bp = art["feature_names"], art["bp_vec"]
#     if names is None or bp.shape[0] != X_dense_rows.shape[1]:
#         return [[] for _ in range(len(X_dense_rows))]
#     delta = X_dense_rows - bp
#     top = np.argsort(-delta, axis=1)[:, :top_k]
#     return [[str(names[c]) for c in cols if delta[r, c] > 0] for r, cols in enumerate(top)]


# def scan_in_chunks(df, art, prefix, model_name):
#     """Preprocess + predict a slice at a time so memory stays small on big files."""
#     n = len(df)
#     preds = np.zeros(n, dtype=int)
#     scores = np.zeros(n, dtype=np.float64)
#     sims = np.zeros(n, dtype=np.float32)
#     events = {}
#     for s in range(0, n, CHUNK_ROWS):
#         e = min(n, s + CHUNK_ROWS)
#         X_s, X_dense, sim = preprocess(df.iloc[s:e], art)
#         p, sc = run_model(prefix, model_name, X_s, art["meta"])
#         p = np.asarray(p).astype(int)
#         sc = np.nan_to_num(np.asarray(sc, dtype=np.float64))
#         preds[s:e], scores[s:e], sims[s:e] = p, sc, sim
#         hit = np.flatnonzero(p == 1)
#         if len(hit):
#             for i, ev in zip(hit, top_events(X_dense[hit], art)):
#                 events[s + int(i)] = ev
#         print(f"[{prefix}/{model_name}] processed {e:,}/{n:,} rows", flush=True)
#     return preds, scores, sims, events


# def severity_of(score):
#     for limit, name in SEVERITY_BANDS:
#         if score >= limit:
#             return name
#     return "low"


# def severity_counts(scores):
#     counts = {name: 0 for _, name in SEVERITY_BANDS}
#     remaining = np.ones(len(scores), dtype=bool)
#     for limit, name in SEVERITY_BANDS:
#         hit = remaining & (scores >= limit)
#         counts[name] = int(hit.sum())
#         remaining &= ~hit
#     counts["low"] = int(remaining.sum())
#     return counts


# def build_threat_meta(keep, scores, sim, events):
#     out = []
#     for i in keep:
#         score = float(scores[i])
#         out.append({
#             "row": int(i) + 1,
#             "score": round(score, 4),
#             "severity": severity_of(score),
#             "similarity_to_normal": round(float(sim[i]), 4),
#             "unusual_events": events.get(int(i), []),
#         })
#     return out


# NORMAL_LABELS = {"normal", "benign", "0", "0.0", "false", "none"}


# def compute_metrics(df_original, predictions):
#     try:
#         col = next((c for c in df_original.columns if str(c).strip().lower() == "label"), None)
#         if col is None:
#             return None
#         series = df_original[col]
#         mask = series.notna().to_numpy()
#         if mask.sum() == 0:
#             return None

#         labelled = series[mask]
#         if pd.api.types.is_numeric_dtype(labelled):
#             y_true = (labelled.astype(float) != 0).astype(int).to_numpy()
#         else:
#             y_true = (~labelled.astype(str).str.strip().str.lower().isin(NORMAL_LABELS)).astype(int).to_numpy()
#         y_pred = np.asarray(predictions).astype(int)[mask]

#         tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
#         return {
#             "label_column": str(col),
#             "labelled_records": int(mask.sum()),
#             "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
#             "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
#             "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
#             "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
#             "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
#         }
#     except Exception:
#         return None


# def _json_default(o):
#     if hasattr(o, "item"):          # numpy scalars
#         return o.item()
#     return str(o)


# def make_response(result, label):
#     """Serialize once, log the size, and send plain JSON (faster than FastAPI's encoder)."""
#     t = time.time()
#     body = json.dumps(result, default=_json_default, allow_nan=False, separators=(",", ":"))
#     print(f"[{label}] response ready: {len(body) / 1e6:.1f} MB, serialized in {time.time() - t:.1f}s", flush=True)
#     return Response(content=body, media_type="application/json")


# @app.get("/")
# def root():
#     return {"service": "AI-SIEM API", "version": "3.0", "docs": "/docs", "health": "/health"}


# @app.get("/health")
# def health():
#     return {"status": "ok"}


# @app.get("/schema/{dataset}")
# def schema(dataset: DatasetEnum):
#     try:
#         art = load_artifacts(dataset.value)
#         return {
#             "dataset": dataset.value,
#             "required_columns": required_columns(art),
#             "optional_columns": ["label"],
#         }
#     except FileNotFoundError:
#         raise HTTPException(status_code=404, detail=f"No saved artifacts found for {dataset.value}.")
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))


# # Plain "def" (not async): FastAPI runs these in a worker thread,
# # so /health keeps answering while a scan is running.
# @app.post("/predict")
# def predict(
#     dataset: DatasetEnum = Form(...),
#     model_type: ModelEnum = Form(...),
#     file: UploadFile = File(...),
# ):
#     try:
#         with SCAN_LOCK:
#             started = time.time()
#             prefix = dataset.value

#             df_original, df_feat, art = read_and_prepare(file, prefix)

#             predictions, scores, sim, events = scan_in_chunks(df_feat, art, prefix, model_type.value)

#             label_map = {0: "normal", 1: "attack"}
#             results = [label_map[p] for p in predictions.tolist()]

#             total_records = len(results)
#             threat_count = results.count("attack")
#             normal_count = total_records - threat_count

#             df_original["predicted_status"] = results

#             threat_idx = np.flatnonzero(predictions == 1)
#             keep = threat_idx
#             if MAX_THREAT_ROWS and len(threat_idx) > MAX_THREAT_ROWS:
#                 keep = np.sort(threat_idx[np.argsort(-scores[threat_idx])[:MAX_THREAT_ROWS]])

#             df_threats = df_original.iloc[keep].astype(object)
#             df_threats = df_threats.where(pd.notna(df_threats), None)
#             threat_details = df_threats.to_dict(orient="records")

#             threat_meta = build_threat_meta(keep, scores, sim, events)

#             result = {
#                 "summary": {
#                     "total_records": total_records,
#                     "normal_traffic": normal_count,
#                     "detected_threats": threat_count,
#                     "severity_counts": severity_counts(scores[threat_idx]),
#                     "threats_returned": len(threat_details),
#                     "threats_truncated": len(threat_details) < threat_count,
#                     "dataset": prefix,
#                     "model_type": model_type.value,
#                     "elapsed_seconds": round(time.time() - started, 2),
#                 },
#                 "threat_details": threat_details,
#                 "threat_meta": threat_meta,
#                 "metrics": compute_metrics(df_original, predictions),
#             }
#             return make_response(result, "predict")

#     except InputError as e:
#         raise HTTPException(status_code=422, detail=str(e))
#     except HTTPException:
#         raise
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))


# @app.post("/compare")
# def compare(
#     dataset: DatasetEnum = Form(...),
#     file: UploadFile = File(...),
# ):
#     try:
#         with SCAN_LOCK:
#             prefix = dataset.value
#             df_original, df_feat, art = read_and_prepare(file, prefix, COMPARE_MAX_ROWS)
#             X_s = np.vstack([
#                 preprocess(df_feat.iloc[a:a + CHUNK_ROWS], art)[0]
#                 for a in range(0, len(df_feat), CHUNK_ROWS)
#             ])
#             total = len(df_original)

#             rows, preds_by_model = [], {}
#             for m in ModelEnum:
#                 started = time.time()
#                 try:
#                     preds, _ = run_model(prefix, m.value, X_s, art["meta"], want_scores=False)
#                     preds = np.asarray(preds).astype(int)
#                     preds_by_model[m.value] = preds

#                     threats = int(preds.sum())
#                     row = {
#                         "model": m.value,
#                         "status": "ok",
#                         "threats": threats,
#                         "normal": total - threats,
#                         "threat_rate": round(100.0 * threats / total, 2),
#                         "seconds": round(time.time() - started, 2),
#                     }
#                     metrics = compute_metrics(df_original, preds)
#                     if metrics:
#                         row["metrics"] = metrics
#                 except Exception as e:
#                     row = {"model": m.value, "status": "error", "detail": str(e)}
#                 rows.append(row)

#             agreement = None
#             ok = len(preds_by_model)
#             if ok >= 2:
#                 votes = np.sum(list(preds_by_model.values()), axis=0)
#                 majority = (votes * 2 > ok).astype(int)
#                 agreement = {
#                     "models_compared": ok,
#                     "unanimous_threat": int((votes == ok).sum()),
#                     "unanimous_normal": int((votes == 0).sum()),
#                     "split": int(((votes > 0) & (votes < ok)).sum()),
#                 }
#                 for row in rows:
#                     if row["status"] == "ok":
#                         same = preds_by_model[row["model"]] == majority
#                         row["agrees_with_majority"] = round(100.0 * float(same.mean()), 2)

#             return make_response(
#                 {"dataset": prefix, "total_records": total, "models": rows, "agreement": agreement}, "compare"
#             )

#     except InputError as e:
#         raise HTTPException(status_code=422, detail=str(e))
#     except HTTPException:
#         raise
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))



import os

# Quieter, lighter TensorFlow (must be set before importing tensorflow)
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
os.environ.setdefault("TF_ENABLE_ONEDNN_OPTS", "0")

import re
import json
import time
import pickle
import threading
from enum import Enum
from functools import lru_cache

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from huggingface_hub import hf_hub_download
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.metrics.pairwise import cosine_similarity

BASE_DIR = os.getenv("MODEL_DIR") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "saved_models")
HF_REPO = os.getenv("HF_REPO", "Rithvik-3103/cyber-ann-models")
HF_REPO_TYPE = "model"
HF_TOKEN = None
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "30"))
MAX_THREAT_ROWS = int(os.getenv("MAX_THREAT_ROWS", "2000"))
MAX_ROWS = int(os.getenv("MAX_ROWS", "100000"))                  # /predict row limit
COMPARE_MAX_ROWS = int(os.getenv("COMPARE_MAX_ROWS", "30000"))   # /compare row limit (8 models)
CHUNK_ROWS = int(os.getenv("CHUNK_ROWS", "20000"))               # rows processed at a time
SEVERITY_BANDS = ((0.90, "high"), (0.70, "medium"))

os.makedirs(BASE_DIR, exist_ok=True)

# One heavy job at a time: protects a small instance from running out of RAM
SCAN_LOCK = threading.Lock()


# ==========================================
# LAZY ARTIFACT DOWNLOAD (Hugging Face)
# Files are fetched the first time they are needed, so the server
# starts instantly and Render's port check passes.
# ==========================================
def ensure_file(filename):
    path = os.path.join(BASE_DIR, filename)

    if os.path.isfile(path):
        print(f"[MODEL] Using local file: {filename}", flush=True)
        return path

    print(
        f"[HF] Downloading {filename} from model repository: {HF_REPO}",
        flush=True,
    )

    try:
        downloaded_path = hf_hub_download(
            repo_id=HF_REPO,
            repo_type="model",
            filename=filename,
            token=False,
        )

        import shutil
        shutil.copy2(downloaded_path, path)

        print(f"[HF] Download successful: {filename}", flush=True)
        return path

    except Exception as exc:
        print(
            f"[HF] Download failed: {filename} | "
            f"{type(exc).__name__}: {exc}",
            flush=True,
        )
        raise
app = FastAPI(title="AI-SIEM Multi-Dataset Intrusion Detection API")

# Set ALLOWED_ORIGINS in Render to your frontend origin, for example:
# https://your-frontend-name.onrender.com
# Multiple origins can be comma-separated. "*" is allowed for public APIs
# when credentials/cookies are not used.
raw_origins = os.getenv("ALLOWED_ORIGINS", "*")
origins = [
    origin.strip().rstrip("/")
    for origin in raw_origins.split(",")
    if origin.strip()
]
if not origins:
    origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class DatasetEnum(str, Enum):
    nsl_kdd = "nsl_kdd"
    cicids2017 = "cicids2017"
    unsw_nb15 = "unsw_nb15"


class ModelEnum(str, Enum):
    svm = "svm"
    knn = "knn"
    random_forest = "random_forest"
    naive_bayes = "naive_bayes"
    decision_tree = "decision_tree"
    fcnn = "fcnn"
    cnn = "cnn"
    lstm = "lstm"


def sanitize(name):
    return re.sub(r"[^0-9a-zA-Z]+", "_", str(name).strip()).strip("_").lower()


class EventEncoder:
    def __init__(self, n_bins=10):
        self.n_bins = n_bins
        self.num_cols, self.cat_cols, self.edges = [], [], {}

    def transform(self, df):
        cols = []
        for c in self.num_cols:
            e = self.edges[c]
            idx = np.searchsorted(e, df[c].to_numpy(dtype=np.float64), side="left")
            lut = np.array([f"{sanitize(c)}_b{i}" for i in range(len(e) + 1)], dtype=object)
            cols.append(lut[idx])
        for c in self.cat_cols:
            s = df[c].astype(str).str.strip().str.lower().str.replace(r"\s+", "_", regex=True)
            cols.append((sanitize(c) + "_" + s).to_numpy(dtype=object))
        mat = np.column_stack(cols)
        return [" ".join(row) for row in mat]

    def load_state(self, state_dict):
        self.n_bins = state_dict["n_bins"]
        self.num_cols = state_dict["num_cols"]
        self.cat_cols = state_dict["cat_cols"]
        self.edges = state_dict["edges"]
        return self


def clean_dataframe(df):
    d = df.replace([np.inf, -np.inf], np.nan)
    for c in d.select_dtypes(include=[np.number]).columns:
        if d[c].isna().any():
            d[c] = d[c].fillna(d[c].median())
    for c in [c for c in d.columns if not pd.api.types.is_numeric_dtype(d[c])]:
        if d[c].isna().any():
            mode_val = d[c].mode()
            d[c] = d[c].fillna(mode_val.iloc[0] if not mode_val.empty else "unknown")
    return d


def to_sequence(X, steps=32):
    n, f = X.shape
    pad = (-f) % steps
    if pad:
        X = np.hstack([X, np.zeros((n, pad), dtype=X.dtype)])
    return X.reshape(n, steps, -1)


@lru_cache(maxsize=3)
def load_artifacts(prefix):
    def _load(suffix):
        with open(ensure_file(f"{prefix}_{suffix}.pkl"), "rb") as f:
            return pickle.load(f)

    enc = EventEncoder().load_state(_load("event_encoder"))
    vec = _load("vectorizer")
    basepoint = _load("basepoint")
    scaler = _load("scaler")
    meta = _load("meta")

    try:
        feature_names = np.asarray(vec.get_feature_names_out())
    except Exception:
        feature_names = None

    bp = basepoint.toarray() if hasattr(basepoint, "toarray") else basepoint
    bp_vec = np.asarray(bp, dtype=np.float64).reshape(-1)

    return {
        "enc": enc, "vec": vec, "basepoint": basepoint, "scaler": scaler,
        "meta": meta, "feature_names": feature_names, "bp_vec": bp_vec,
    }


# Small caches keep memory low on small instances
@lru_cache(maxsize=2)
def load_dl_model(filename):
    # TensorFlow is imported only when a deep-learning model is first used.
    # This keeps idle memory low, so ML models and /health work on small instances.
    import tensorflow as tf
    return tf.keras.models.load_model(ensure_file(filename), compile=False)


@lru_cache(maxsize=3)
def load_ml_model(filename):
    return joblib.load(ensure_file(filename))


def preprocess(df, art):
    ev_data = art["enc"].transform(df)
    X_vec = art["vec"].transform(ev_data)
    sim = cosine_similarity(X_vec, art["basepoint"]).astype(np.float32)
    X_dense = X_vec.toarray()
    X_p = np.hstack([X_dense, sim])
    X_s = art["scaler"].transform(X_p).astype(np.float32)
    np.clip(X_s, -art["meta"]["clip"], art["meta"]["clip"], out=X_s)
    return X_s, X_dense, sim.max(axis=1)


class InputError(ValueError):
    pass


def required_columns(art):
    return [str(c) for c in (*art["enc"].num_cols, *art["enc"].cat_cols)]


def check_required_columns(df, art, prefix):
    required = required_columns(art)
    present = {str(c) for c in df.columns}
    missing = [c for c in required if c not in present]
    if missing:
        shown = ", ".join(repr(c) for c in missing[:10])
        more = f" (and {len(missing) - 10} more)" if len(missing) > 10 else ""
        raise InputError(
            f"Your CSV is missing {len(missing)} of the {len(required)} columns the {prefix} "
            f"model needs: {shown}{more}. Check that you picked the right dataset."
        )


def read_and_prepare(file, prefix, max_rows=None):
    max_rows = max_rows or MAX_ROWS
    # Enforce the upload limit on the server too
    file.file.seek(0, os.SEEK_END)
    size = file.file.tell()
    file.file.seek(0)
    if size > MAX_UPLOAD_MB * 1024 * 1024:
        raise InputError(f"File is {size / 1024 / 1024:.1f} MB. The server limit is {MAX_UPLOAD_MB} MB.")

    try:
        raw = pd.read_csv(file.file, nrows=max_rows + 1)  # stop reading early if the file is too long
    except Exception as e:
        raise InputError(f"Could not read the file as a CSV: {e}")
    if raw.empty:
        raise InputError("The uploaded CSV has no rows.")
    if len(raw) > max_rows:
        raise InputError(
            f"This CSV has more than {max_rows:,} rows, which is the limit for this server. "
            "Upload a smaller sample or split the file."
        )

    # Keep the label column out of cleaning so unlabelled rows stay unlabelled
    label_col = next((c for c in raw.columns if str(c).strip().lower() == "label"), None)
    labels = raw[label_col].copy() if label_col is not None else None
    features = raw.drop(columns=[label_col]) if label_col is not None else raw

    df = clean_dataframe(features)
    art = load_artifacts(prefix)
    check_required_columns(df, art, prefix)

    df_original = df.copy()
    if labels is not None:
        df_original[label_col] = labels.to_numpy()
    return df_original, df, art


def predict_fcnn(model, X_s, dataset_name):
    probs = model.predict(X_s, batch_size=1024, verbose=0).ravel()
    if dataset_name == "cicids2017":
        scores = np.power(probs, 0.65)
        predictions = (scores >= 0.01).astype(int)
    else:
        scores = probs
        predictions = (probs >= 0.5).astype(int)
    return predictions, scores


def predict_cnn_lstm(model, X_s, model_type, meta):
    if model_type == "cnn":
        X_input = X_s[..., np.newaxis]
    elif model_type == "lstm":
        X_input = to_sequence(X_s, steps=meta.get("lstm_steps", 32))
    else:
        X_input = X_s

    probs = model.predict(X_input, batch_size=1024, verbose=0).ravel()
    return (probs >= 0.5).astype(int), probs


def predict_ml_model(model, X_s, want_scores=True):
    predictions = np.asarray(model.predict(X_s)).astype(int)
    scores = None

    if want_scores and hasattr(model, "predict_proba"):
        try:
            proba = model.predict_proba(X_s)
            classes = list(getattr(model, "classes_", [0, 1]))
            col = classes.index(1) if 1 in classes else proba.shape[1] - 1
            scores = proba[:, col]
        except Exception:
            scores = None

    if want_scores and scores is None and hasattr(model, "decision_function"):
        try:
            d = np.asarray(model.decision_function(X_s)).ravel()
            scores = 1.0 / (1.0 + np.exp(-np.clip(d, -30, 30)))
        except Exception:
            scores = None

    if scores is None:
        scores = predictions.astype(float)
    return predictions, scores


def run_model(prefix, model_name, X_s, meta, want_scores=True):
    if model_name == "fcnn":
        model = load_dl_model(f"{prefix}_dl_fcnn.keras")
        return predict_fcnn(model, X_s, prefix)
    if model_name in ("cnn", "lstm"):
        model = load_dl_model(f"{prefix}_dl_{model_name}.keras")
        return predict_cnn_lstm(model, X_s, model_name, meta)
    model = load_ml_model(f"{prefix}_ml_{model_name}.pkl")
    return predict_ml_model(model, X_s, want_scores)


def top_events(X_dense_rows, art, top_k=3):
    names, bp = art["feature_names"], art["bp_vec"]
    if names is None or bp.shape[0] != X_dense_rows.shape[1]:
        return [[] for _ in range(len(X_dense_rows))]
    delta = X_dense_rows - bp
    top = np.argsort(-delta, axis=1)[:, :top_k]
    return [[str(names[c]) for c in cols if delta[r, c] > 0] for r, cols in enumerate(top)]


def scan_in_chunks(df, art, prefix, model_name):
    """Preprocess + predict a slice at a time so memory stays small on big files."""
    n = len(df)
    preds = np.zeros(n, dtype=int)
    scores = np.zeros(n, dtype=np.float64)
    sims = np.zeros(n, dtype=np.float32)
    events = {}
    for s in range(0, n, CHUNK_ROWS):
        e = min(n, s + CHUNK_ROWS)
        X_s, X_dense, sim = preprocess(df.iloc[s:e], art)
        p, sc = run_model(prefix, model_name, X_s, art["meta"])
        p = np.asarray(p).astype(int)
        sc = np.nan_to_num(np.asarray(sc, dtype=np.float64))
        preds[s:e], scores[s:e], sims[s:e] = p, sc, sim
        hit = np.flatnonzero(p == 1)
        if len(hit):
            for i, ev in zip(hit, top_events(X_dense[hit], art)):
                events[s + int(i)] = ev
        print(f"[{prefix}/{model_name}] processed {e:,}/{n:,} rows", flush=True)
    return preds, scores, sims, events


def severity_of(score):
    for limit, name in SEVERITY_BANDS:
        if score >= limit:
            return name
    return "low"


def severity_counts(scores):
    counts = {name: 0 for _, name in SEVERITY_BANDS}
    remaining = np.ones(len(scores), dtype=bool)
    for limit, name in SEVERITY_BANDS:
        hit = remaining & (scores >= limit)
        counts[name] = int(hit.sum())
        remaining &= ~hit
    counts["low"] = int(remaining.sum())
    return counts


def build_threat_meta(keep, scores, sim, events):
    out = []
    for i in keep:
        score = float(scores[i])
        out.append({
            "row": int(i) + 1,
            "score": round(score, 4),
            "severity": severity_of(score),
            "similarity_to_normal": round(float(sim[i]), 4),
            "unusual_events": events.get(int(i), []),
        })
    return out


NORMAL_LABELS = {"normal", "benign", "0", "0.0", "false", "none"}


def compute_metrics(df_original, predictions):
    try:
        col = next((c for c in df_original.columns if str(c).strip().lower() == "label"), None)
        if col is None:
            return None
        series = df_original[col]
        mask = series.notna().to_numpy()
        if mask.sum() == 0:
            return None

        labelled = series[mask]
        if pd.api.types.is_numeric_dtype(labelled):
            y_true = (labelled.astype(float) != 0).astype(int).to_numpy()
        else:
            y_true = (~labelled.astype(str).str.strip().str.lower().isin(NORMAL_LABELS)).astype(int).to_numpy()
        y_pred = np.asarray(predictions).astype(int)[mask]

        tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
        return {
            "label_column": str(col),
            "labelled_records": int(mask.sum()),
            "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
            "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
            "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        }
    except Exception:
        return None


def _json_default(o):
    if hasattr(o, "item"):          # numpy scalars
        return o.item()
    return str(o)


def make_response(result, label):
    """Serialize once, log the size, and send plain JSON (faster than FastAPI's encoder)."""
    t = time.time()
    body = json.dumps(result, default=_json_default, allow_nan=False, separators=(",", ":"))
    print(f"[{label}] response ready: {len(body) / 1e6:.1f} MB, serialized in {time.time() - t:.1f}s", flush=True)
    return Response(content=body, media_type="application/json")


@app.get("/")
def root():
    return {"service": "AI-SIEM API", "version": "3.0", "docs": "/docs", "health": "/health"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/schema/{dataset}")
def schema(dataset: DatasetEnum):
    try:
        art = load_artifacts(dataset.value)
        return {
            "dataset": dataset.value,
            "required_columns": required_columns(art),
            "optional_columns": ["label"],
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"No saved artifacts found for {dataset.value}.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Plain "def" (not async): FastAPI runs these in a worker thread,
# so /health keeps answering while a scan is running.
@app.post("/predict")
def predict(
    dataset: DatasetEnum = Form(...),
    model_type: ModelEnum = Form(...),
    file: UploadFile = File(...),
):
    try:
        with SCAN_LOCK:
            started = time.time()
            prefix = dataset.value

            df_original, df_feat, art = read_and_prepare(file, prefix)

            predictions, scores, sim, events = scan_in_chunks(df_feat, art, prefix, model_type.value)

            label_map = {0: "normal", 1: "attack"}
            results = [label_map[p] for p in predictions.tolist()]

            total_records = len(results)
            threat_count = results.count("attack")
            normal_count = total_records - threat_count

            df_original["predicted_status"] = results

            threat_idx = np.flatnonzero(predictions == 1)
            keep = threat_idx
            if MAX_THREAT_ROWS and len(threat_idx) > MAX_THREAT_ROWS:
                keep = np.sort(threat_idx[np.argsort(-scores[threat_idx])[:MAX_THREAT_ROWS]])

            df_threats = df_original.iloc[keep].astype(object)
            df_threats = df_threats.where(pd.notna(df_threats), None)
            threat_details = df_threats.to_dict(orient="records")

            threat_meta = build_threat_meta(keep, scores, sim, events)

            result = {
                "summary": {
                    "total_records": total_records,
                    "normal_traffic": normal_count,
                    "detected_threats": threat_count,
                    "severity_counts": severity_counts(scores[threat_idx]),
                    "threats_returned": len(threat_details),
                    "threats_truncated": len(threat_details) < threat_count,
                    "dataset": prefix,
                    "model_type": model_type.value,
                    "elapsed_seconds": round(time.time() - started, 2),
                },
                "threat_details": threat_details,
                "threat_meta": threat_meta,
                "metrics": compute_metrics(df_original, predictions),
            }
            return make_response(result, "predict")

    except InputError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/compare")
def compare(
    dataset: DatasetEnum = Form(...),
    file: UploadFile = File(...),
):
    try:
        with SCAN_LOCK:
            prefix = dataset.value
            df_original, df_feat, art = read_and_prepare(file, prefix, COMPARE_MAX_ROWS)
            X_s = np.vstack([
                preprocess(df_feat.iloc[a:a + CHUNK_ROWS], art)[0]
                for a in range(0, len(df_feat), CHUNK_ROWS)
            ])
            total = len(df_original)

            rows, preds_by_model = [], {}
            for m in ModelEnum:
                started = time.time()
                try:
                    preds, _ = run_model(prefix, m.value, X_s, art["meta"], want_scores=False)
                    preds = np.asarray(preds).astype(int)
                    preds_by_model[m.value] = preds

                    threats = int(preds.sum())
                    row = {
                        "model": m.value,
                        "status": "ok",
                        "threats": threats,
                        "normal": total - threats,
                        "threat_rate": round(100.0 * threats / total, 2),
                        "seconds": round(time.time() - started, 2),
                    }
                    metrics = compute_metrics(df_original, preds)
                    if metrics:
                        row["metrics"] = metrics
                except Exception as e:
                    row = {"model": m.value, "status": "error", "detail": str(e)}
                rows.append(row)

            agreement = None
            ok = len(preds_by_model)
            if ok >= 2:
                votes = np.sum(list(preds_by_model.values()), axis=0)
                majority = (votes * 2 > ok).astype(int)
                agreement = {
                    "models_compared": ok,
                    "unanimous_threat": int((votes == ok).sum()),
                    "unanimous_normal": int((votes == 0).sum()),
                    "split": int(((votes > 0) & (votes < ok)).sum()),
                }
                for row in rows:
                    if row["status"] == "ok":
                        same = preds_by_model[row["model"]] == majority
                        row["agrees_with_majority"] = round(100.0 * float(same.mean()), 2)

            return make_response(
                {"dataset": prefix, "total_records": total, "models": rows, "agreement": agreement}, "compare"
            )

    except InputError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))