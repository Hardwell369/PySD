# Django
def django_risk_case1():
    # case 1: nested list container
    condition = "name='" + request.POST.get("username") + "'"
    User.objects.extra(where=[[condition]])

def django_risk_case2():
    # case 2: tuple container
    condition = "name='" + request.POST.get("username") + "'"
    User.objects.extra(where=(condition,))

def django_risk_case3():
    # case 3: multi-parameter mixed container
    condition = "name='" + request.POST.get("username") + "'"
    safe_param = [123]
    User.objects.extra(where=[condition], select=["id"], params=safe_param)

def django_risk_case4():
    user_id = request.GET.get("user_id")
    # case 4: % string formatting concatenation
    User.objects.extra(where=["id=%s" % user_id])

def django_risk_case5():
    # case 5: + string concatenation
    condition = "name='" + request.POST.get("username") + "'"
    User.objects.extra(where=[condition])

def django_safe_case6():
    # case 6: safe parameterization
    user_id = request.GET.get("user_id")
    User.objects.extra(where=["id=%s"], params=[user_id])

def django_risk_case7():
    # case 7: % string formatting concatenation
    user_input = request.GET.get("nickname")
    users = User.objects.extra(where=["nickname = '%s'" % user_input])

def django_safe_case8():
    # case 8: safe parameterization
    user_input = request.GET.get("nickname")
    users = User.objects.extra(where=["nickname = %s"], params=[user_input])

def django_safe_case9():
    # case 9: safe parameterization
    user_id = request.GET.get("user_id")
    users = User.objects.extra(where=("id = %s", (user_id,)))


# FastAPI
@app.get("/user/info")
def fastapi_risk_case1(user_id: str = Query(...)):
    conn = pymysql.connect(host="localhost", user="root", password="123456", db="test")
    cursor = conn.cursor()
    # risk 1: % string formatting concatenation
    sql = "SELECT * FROM user WHERE id=%s" % user_id
    cursor.execute(sql)
    # risk 2: + string concatenation
    sql2 = "DELETE FROM user WHERE name=" + Query(...).name
    cursor.executemany(sql2)
    return cursor.fetchall()


@app.post("/user/add")
def fastapi_safe_case(username: str = Query(...)):
    conn = pymysql.connect(host="localhost", user="root", password="123456", db="test")
    cursor = conn.cursor()
    # safe: parameterization
    sql = "INSERT INTO user (name) VALUES (%s)"
    cursor.execute(sql, (username,))
    conn.commit()
    return {"code": 200}


@app.get("/items")
async def fastapi_risk_case2(request: Request):
    search_term = request.query_params.get("category")
    # risk 3: f-string concatenation
    query = f"SELECT * FROM items WHERE category = '{search_term}'"
    result = await database.fetch_all(query=query)

@app.get("/orders")
async def fastapi_risk_case3(request: Request):
    sort_column = request.query_params.get("sort") 
    # risk 4: f-string concatenation
    sql = f"SELECT * FROM orders ORDER BY {sort_column} DESC"
    # even though it's parameterized, the {sort_column} is still a risk
    cursor.execute(sql, (user_id,))

@app.get("/orders")
async def fastapi_risk_case4(request: Request):
    sort_column = request.query_params.get("sort")
    # risk 5: + string concatenation
    sql = "SELECT * FROM orders ORDER BY" + sort_column + " DESC"
    # even though it's parameterized, the {sort_column} is still a risk
    cursor.execute(sql, (user_id,))

@app.post("/user/activate")
async def fastapi_risk_case5(request: Request):
    from databases import Database
    db = Database("postgresql://...")
    email = request.form.get("email")
    # risk 6: % string concatenation
    query = "UPDATE users SET is_active = TRUE WHERE email = '%s'" % email
    await db.execute(query=query)
    return {"code": 200}

@app.post("/users/async/asyncpg")
async def fastapi_risk_case6(request: Request):
    user_email = (await request.form()).get("email", "")
    # risk 7: % string concatenation
    sql_query = "UPDATE users SET is_active = TRUE WHERE email = '%s'" % user_email
    async with pg_pool.acquire() as conn:
        affected_rows = await conn.execute(sql_query)
    return {"affected_rows": affected_rows, "message": "update user status success"}

@app.get("/orders/async/aiomysql")
async def fastapi_risk_case7(request: Request) -> Dict:
    sort_column = request.query_params.get("sort", "id")
    # risk 8: + string concatenation
    sql_query = "SELECT * FROM orders ORDER BY " + sort_column + " DESC LIMIT 10"
    async with mysql_pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            await cur.execute(sql_query)
            orders = await cur.fetchall()
    return {"total": len(orders), "orders": orders}

@app.get("/user/{user_id}")
def fastapi_risk_case8(user_id: int = Path(...)):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    # risk 9: + string concatenation
    sql = "SELECT * FROM users WHERE id = " + str(user_id)
    cursor.execute(sql)
    result = cursor.fetchone()
    conn.close()
    return {"user": result}

@app.get("/articles")
def fastapi_risk_case9(category: str = Query(...)):
    # risk 10: + string concatenation in text(), which is not parameterized
    # correct way: text("SELECT * FROM articles WHERE category = :category").params(category=category)
    sql = text(f"SELECT * FROM articles WHERE category = '{category}'")
    with engine.connect() as conn:
        result = conn.execute(sql).fetchall()
    return {"articles": result}

@app.get("/articles/filter")
def fastapi_risk_case10(keyword: str = Query(...)):
    db = SessionLocal()
    # risk 11: f-string concatenation in SQL, which is not parameterized
    filter_str = f"title LIKE '%{keyword}%'"
    articles = db.query(Article).filter(text(filter_str)).all()
    db.close()
    return {"articles": articles}

def normal_safe_case(user_id: int):
    # safe: log info concatenation, it should not be a risk
    log_info = "user " + str(user_id) + " login success at " + "2025-12-21"
    # safe: str concatenation in normal return, not in web framework's response, it should not be a risk
    response = "response: %s" % 100
    print(log_info, response)
