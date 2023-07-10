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

# Make sure API key is set
# if not os.environ.get("API_KEY"):
#     raise RuntimeError("API_KEY not set")

API_KEY = "pk_126160f035ab4d56b6b8602868c5fbce"


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
    # select logged in user
    account = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])

    # # get balance of the user
    # cash = account[0]["cash"]

    # get current users owned stocks
    holdings = db.execute("SELECT firm, symbol, SUM(shares) as shares FROM holdings WHERE user_id = ? GROUP BY symbol HAVING (SUM(shares)) > 0", session["user_id"])
    # set total value to zero
    total_value = 0
    # loop through user's holdings
    for holding in holdings:
        # get quote for each symbol
        quote = lookup(holding["symbol"])
        holding["price"] = quote["price"]
        holding["name"] = quote["name"]
        # get total (shares * price)
        holding["total"] = holding["price"] * holding["shares"]
        # total value
        total_value += holding["total"]

    # grand total, stocks total value plus cash
    grand_total = total_value + account[0]["cash"]

    return render_template(
        "index.html", holdings = holdings, account = account[0]["cash"], grand_total=grand_total
    )



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # If user reached route via post
    if request.method == "POST":
        # get symbol
        symbol = request.form.get("symbol")
        # look up price
        quote = lookup(symbol)
        # check for available cash
        capital = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])

        # get shares and check if positive integer
        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("Shares must be a positive integer")
        if not symbol:
            return apology("Provide a valid symbol")
        elif not quote:
            return apology("Invalid symbol")
        elif not shares:
            return apology("Please provide amount of shares")
        # check if shares is digits
        # elif not str.isdigit(shares):
        #     return apology("shares must be digits")
        # make sure shares isn't less than 1
        elif shares < 1:
            return apology("shares should be greater than zero")

        # get available cash
        balance = capital[0]["cash"]
        # name of shares
        firm = quote["name"]
        # price per share
        price = quote["price"]
        # total price of shares
        total_price = int(shares) * float(price)

        # check if user can afford stocks
        if balance < total_price:
            return apology("Insufficient funds")

        else:
            available = balance - total_price
            # update available balance
            db.execute("UPDATE users SET cash = ? WHERE id = ?", available, session["user_id"])
            # add to user's holdings table
            db.execute("INSERT INTO holdings(user_id, firm, symbol, shares, price, transaction_type) VALUES (?, ?, ?, ?, ?, ?)",
                       session["user_id"], firm, symbol, shares, price, "buy")

            flash("Successful!")

        return redirect("/")


    else:
        return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Get all transactions from users holdings table
    transactions = db.execute("SELECT * FROM holdings WHERE user_id = ?", session["user_id"])

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
    if request.method == "POST":
        # get quote
        symbol = request.form.get("symbol")

        # Ensure user submitted a quote
        if not symbol:
            return apology("No symbol submitted")

        # lookup quote
        quote = lookup(symbol)
        # Check if quote is empty
        if quote is None:
            return apology("must submit a valid symbol")
        else:
            # lookup a symbol's current quote using lookup

            return render_template("quoted.html",
                                   name =quote["name"],
                                   symbol = quote["symbol"],
                                   price = quote["price"])
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # get username
        username = request.form.get("username")

        # check if username in database
        confirm = db.execute("SELECT * FROM users WHERE username = ?", username)

        # get passswords
        password1 = request.form.get("password")
        password2 = request.form.get("confirmation")

        # check if username was provided
        if not username:
            return apology("Usename field cannot be blank")

        if len(username) < 5:
            return apology("Username cannot be less than 5 characters")

        # check if password was submitted
        elif not password1:
            return apology ("must enter a password", 400)

        # ensure passwords match
        elif password1 != password2:
            return apology("passwords must match", 400)

        elif len(confirm) > 0:
            return apology("username already exists", 400)

        else:
            # https://tedboy.github.io/flask/generated/werkzeug.generate_password_hash.html#:~:text=Hash%20a%20password%20with%20the,()%20can%20check%20the%20hash.
            passwordHash = generate_password_hash(password1, method='pbkdf2:sha256',salt_length=8)

            # add new users login details to database
            db.execute("INSERT INTO users(username, hash) VALUES(?, ?)", username, passwordHash)

            # select users from database
            rows = db.execute("SELECT * FROM users WHERE username = ?", username)

            #  add to session id
            session["user_id"] = rows[0]["id"]

            # flash a message
            flash("You've been registered")

            # redirect to homepage
            return redirect("/")

    # if user reached route via GET
    else:
        return render_template("register.html")



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # If user reaches route by post
    if request.method == "POST":

        # get the symbol
        symbol = request.form.get("symbol")

        # get number of shares
        shares = request.form.get("shares")

        # lookup symbol
        quote = lookup(symbol)

        try:
            shares = int(shares)
            if shares < 1:
                return apology("Minimun shares to sell is 1")
        except ValueError:
            return apology("Shares must be a number")

        # Validate user inputs
        if not symbol:
            return apology("Please input a symbol")
        elif not shares:
            return apology("Number of shares is required")

        elif not quote:
            return apology("Invalid symbol")

        # get price
        price = quote["price"]
        name = quote["name"]
        # total_value
        total = price * shares

        # check database if user has stocks
        rows = db.execute("SELECT SUM(shares) as shares FROM holdings WHERE user_id = ? AND symbol = ?", session["user_id"], symbol)
        stocks = int(rows[0]["shares"])

        # ensure user has enough shares for sale
        if not stocks or shares > stocks:
            return apology("You don't have enough shares available to sell")

        # insert transaction into table substracting available shares
        db.execute("INSERT INTO holdings (user_id, firm, symbol, shares, price, transaction_type ) VALUES(?, ?, ?, ?, ?, ?)",
                   session["user_id"], name, symbol.upper(), -shares, price, "sell")

        # update cash available and update cash available
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", total, session["user_id"] )

        flash("Sold successfully")
        return redirect("/")

    else:
        # display available owned stocks
        stocks = db.execute("SELECT * FROM holdings WHERE user_id = ? GROUP BY symbol ORDER BY COUNT(shares) ASC", session["user_id"])
        return render_template("sell.html", stocks = stocks)


@app.route("/change_password", methods = ["GET", "POST"])
def change_password():
    """Allow users change their password"""
    if request.method == "POST":
        # get password
        password = request.form.get("password")

        if not password:
            return apology("Input password")

        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        # get stored password
        confirm = check_password_hash(rows[0]["hash"], password)

        if not confirm:
            return apology("Incorrect password")

        # get new password
        new_password = request.form.get("new_password")
        if not new_password:
            return apology("Input new password")

        # get password confirmation
        new_password2 = request.form.get("new_password2")
        if not new_password2:
            return apology("Confirm password")

        # ensure passwords match
        if new_password != new_password2:
            return apology("Passwords do not match")

        # generate password hash
        password_hash = generate_password_hash(new_password)
        # update user table with the new password
        db.execute("UPDATE users SET hash = ? WHERE id = ?", password_hash, session["user_id"] )

        flash("Successfully changed password")

        return redirect("/")

    else:
        return render_template("change_password.html")





