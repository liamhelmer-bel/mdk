import ctypes as c, json, os, pathlib, subprocess, sys, tempfile

s = c.CDLL(os.environ["PROBE_SQLCIPHER_LIBRARY"])
s.sqlite3_open.argtypes = [c.c_char_p, c.POINTER(c.c_void_p)]
s.sqlite3_close.argtypes = [c.c_void_p]
s.sqlite3_exec.argtypes = [
    c.c_void_p,
    c.c_char_p,
    c.c_void_p,
    c.c_void_p,
    c.POINTER(c.c_char_p),
]
s.sqlite3_get_autocommit.argtypes = [c.c_void_p]
s.sqlite3_libversion.restype = c.c_char_p
s.sqlite3_errmsg.argtypes = [c.c_void_p]
s.sqlite3_errmsg.restype = c.c_char_p
cbtype = c.CFUNCTYPE(
    c.c_int, c.c_void_p, c.c_int, c.POINTER(c.c_char_p), c.POINTER(c.c_char_p)
)


def run(db, sql):
    rows = []

    @cbtype
    def cb(_, n, values, names):
        rows.append([values[i].decode() if values[i] else None for i in range(n)])
        return 0

    rc = s.sqlite3_exec(db, sql.encode(), cb, None, None)
    return {
        "rc": rc,
        "rows": rows,
        "error": s.sqlite3_errmsg(db).decode() if rc else None,
    }


def open_db(p):
    db = c.c_void_p()
    assert s.sqlite3_open(os.fsencode(p), c.byref(db)) == 0
    # Synthetic disposable key only; never reads host accounts or secrets.
    assert run(db, "pragma key='disposable-probe-key';")["rc"] == 0
    return db


if len(sys.argv) > 1:
    db = open_db(sys.argv[1])
    r = run(db, "begin immediate;insert into t values(2);commit;")
    print(json.dumps(r))
    s.sqlite3_close(db)
else:
    helper = c.CDLL(os.environ["PROBE_HELPER_LIBRARY"])
    helper.probe_private_db.argtypes = [c.c_char_p]
    with tempfile.TemporaryDirectory(prefix="mdk-native-lock-probe-") as root:
        p = pathlib.Path(root) / "test.sqlite"
        db = open_db(p)
        v = run(db, "pragma cipher_version;")
        assert run(db, "pragma journal_mode=wal;create table t(n);")["rc"] == 0
        assert run(db, "begin immediate;insert into t values(1);")["rc"] == 0

        def writer():
            return json.loads(
                subprocess.check_output([sys.executable, __file__, str(p)], text=True)
            )

        before = writer()
        assert helper.probe_private_db(os.fsencode(p)) == 0
        after = writer()
        print(
            json.dumps(
                {
                    "probe": "encrypted_sqlcipher_second_writer",
                    "sqlite_version": s.sqlite3_libversion().decode(),
                    "cipher_version": v["rows"],
                    "before": before,
                    "after": after,
                    "parent_transaction_still_open": s.sqlite3_get_autocommit(db) == 0,
                }
            )
        )
        run(db, "rollback;")
        s.sqlite3_close(db)
