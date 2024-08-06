import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Query database for user's cash balance
    rows = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
    cash = rows[0]["cash"]

    # Query database for user's stocks
    rows = db.execute("""SELECT symbol, SUM(shares) as total_shares
                         FROM transactions
                         WHERE user_id = :user_id
                         GROUP BY symbol
                         HAVING total_shares > 0""",
                      user_id=session["user_id"])

    # Create a list to hold portfolio data
    portfolio = []

    # Total value of stocks
    total = 0

    # Iterate over each stock the user owns
    for row in rows:
        stock = lookup(row["symbol"])
        shares = row["total_shares"]
        total_stock_value = shares * stock["price"]
        total += total_stock_value
        portfolio.append({"symbol": stock["symbol"], "name": stock["name"], "shares": shares,
                          "price": usd(stock["price"]), "total": usd(total_stock_value)})

    # Render index template
    return render_template("index.html", stocks=portfolio, cash=usd(cash), total=usd(cash + total))



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide symbol")

        # Ensure number of shares was submitted
        if not request.form.get("shares"):
            return apology("must provide number of shares")

        # Ensure number of shares is a positive integer
        shares = int(request.form.get("shares"))
        if shares < 1:
            return apology("shares must be a positive integer")

        # Lookup stock information
        stock = lookup(request.form.get("symbol"))

        # Ensure symbol exists
        if not stock:
            return apology("invalid symbol")

        # Calculate total cost of purchase
        total_cost = shares * stock["price"]

        # Query database for user's cash
        rows = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = rows[0]["cash"]

        # Ensure user can afford the purchase
        if total_cost > cash:
            return apology("can't afford")

        # Update user's cash and transaction history
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", total_cost, session["user_id"])
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
                   session["user_id"], stock["symbol"], shares, stock["price"])

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("buy.html")



@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    transactions = db.execute("""
        SELECT symbol, shares, price, transacted
        FROM transactions
        WHERE user_id = :user_id
        ORDER BY transacted DESC
    """, user_id=session["user_id"])

    return render_template("history.html", transactions=transactions)



@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide symbol")

        # Lookup stock information
        stock = lookup(request.form.get("symbol"))

        # Ensure symbol exists
        if not stock:
            return apology("invalid symbol")

        # Render quoted template, passing stock information
        return render_template("quoted.html", stock=stock)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password")

        # Ensure confirmation password was submitted and matches the password
        elif not request.form.get("confirmation") or request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match")

        # Hash the user's password
        hash = generate_password_hash(request.form.get("password"))

        # Insert the new user into the users table
        result = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)",
                            username=request.form.get("username"), hash=hash)

        # Ensure username does not already exist
        if not result:
            return apology("username already exists")

        # Remember which user has logged in
        session["user_id"] = result

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)

        # Ensure shares was submitted
        shares = request.form.get("shares")
        if not shares or int(shares) <= 0:
            return apology("must provide positive integer for shares", 403)

        # Ensure user owns the stock
        rows = db.execute("SELECT symbol, SUM(shares) as total_shares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING total_shares > 0", session["user_id"])
        symbols = [row['symbol'] for row in rows]
        if request.form.get("symbol") not in symbols:
            return apology("you don't own any share of this stock", 403)

        # Ensure user owns enough shares of the stock
        for row in rows:
            if row['symbol'] == request.form.get("symbol") and int(shares) > row['total_shares']:
                return apology("you don't own that many shares of this stock", 403)

        # Fetch current price of the stock
        stock = lookup(request.form.get("symbol"))
        if stock is None:
            return apology("invalid symbol", 400)

        # Sell the stock: decrease number of shares and increase cash
        # Remember to record the transaction in the database
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)", session["user_id"], stock['symbol'], -int(shares), stock['price'])
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", stock['price']*int(shares), session["user_id"])

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        # Fetch the symbols of stocks the user owns
        rows = db.execute("SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0", session["user_id"])
        symbols = [row['symbol'] for row in rows]
        return render_template("sell.html", symbols=symbols)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change user's password."""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure current password was submitted
        if not request.form.get("current_password"):
            return apology("must provide current password", 403)

        # Ensure new password was submitted
        if not request.form.get("new_password"):
            return apology("must provide new password", 403)

        # Ensure confirmation password was submitted and matches new password
        if not request.form.get("confirmation") or request.form.get("new_password") != request.form.get("confirmation"):
            return apology("new password and its confirmation must match", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE id = :id", id=session["user_id"])

        # Ensure current password is correct
        if not check_password_hash(rows[0]["hash"], request.form.get("current_password")):
            return apology("invalid current password", 403)

        # Hash the new password
        new_password_hash = generate_password_hash(request.form.get("new_password"))

        # Update the password in the database
        db.execute("UPDATE users SET hash = :new_password_hash WHERE id = :id", new_password_hash=new_password_hash, id=session["user_id"])

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("change_password.html")
