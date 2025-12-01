import tkinter as tk
from tkinter import messagebox, simpledialog, Toplevel, ttk
import bcrypt
import os
import re
from datetime import datetime, timedelta
import uuid

# FIREBASE: Import Firebase libraries
import firebase_admin
from firebase_admin import credentials, db, exceptions

# --- Constants ---
PAY_LATER_DEADLINE_MINUTES = 30
PAY_LATER_NOTIFICATION_MINUTES = 60
BID_TIMEOUT_HOURS = 24

# --- FIREBASE: New constants for Firebase connection ---
FIREBASE_CREDENTIALS_FILE = "firebase_credentials.json"
FIREBASE_DATABASE_URL = "https://movieticketapp-a719f-default-rtdb.firebaseio.com/"

# --- GUI Style Constants ---
BG_COLOR = "#000000";
FG_COLOR = "#FFFFFF";
NEON_RED = "#FF073A";
NEON_RED_HOVER = "#FF406A"
VALID_GREEN = "#00FF00";
ERROR_RED = "#FF0000";
ENTRY_BG = "#1A1A1A";
LISTBOX_BG = "#101010"
FONT_NORMAL = ("Consolas", 12);
FONT_BOLD = ("Consolas", 12, "bold")
FONT_LARGE = ("Consolas", 20, "bold");
FONT_MEDIUM = ("Consolas", 16, "bold")


# --- Helper Function for Date Parsing ---
def parse_show_time(show_time_str, show_id=None, movie_title=None, update_db=False):
    """Parse show_time, handle both YY and YYYY formats, optionally update Firebase."""
    if not show_time_str:
        raise ValueError("No show_time provided")
    try:
        # Try four-digit year
        return datetime.strptime(show_time_str, "%d-%m-%Y %H:%M")
    except ValueError:
        try:
            # Fallback to two-digit year
            dt = datetime.strptime(show_time_str, "%d-%m-%y %H:%M")
            dt = dt.replace(year=dt.year + 2000 if dt.year < 100 else dt.year)
            # Auto-update Firebase if requested
            if update_db and show_id:
                new_time_str = dt.strftime("%d-%m-%Y %H:%M")
                db.reference(f'shows/{show_id}').update({'show_time': new_time_str})
                print(f"Fixed date format for show '{movie_title}' (ID: {show_id}): {show_time_str} → {new_time_str}")
            return dt
        except ValueError:
            raise ValueError(f"Invalid show_time format: {show_time_str}")


# --- Backend Functions ---
def hash_password(password):
    """Hashes a password using bcrypt with salt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)


def check_password(hashed_password, user_password):
    """Verifies a password against the stored bcrypt hash."""
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)


def initialize_firebase():
    """Initializes Firebase and seeds the database if empty."""
    if FIREBASE_DATABASE_URL == "YOUR_DATABASE_URL_HERE" or not FIREBASE_DATABASE_URL:
        messagebox.showerror("Configuration Error", "Please set your FIREBASE_DATABASE_URL in the script.")
        exit()
    if not os.path.exists(FIREBASE_CREDENTIALS_FILE):
        messagebox.showerror("Firebase Error", f"Credentials file '{FIREBASE_CREDENTIALS_FILE}' not found.")
        exit()
    try:
        cred = credentials.Certificate(FIREBASE_CREDENTIALS_FILE)
        firebase_admin.initialize_app(cred, {'databaseURL': FIREBASE_DATABASE_URL})
        print("Successfully connected to Firebase.")
        admin_ref = db.reference('users/admin')
        if admin_ref.get() is None:
            admin_pass = "Breakingbad@123"
            admin_ref.set({"password": hash_password(admin_pass).decode('utf-8'), "role": "admin"})
            print("Created default admin user in Firebase.")
    except Exception as e:
        messagebox.showerror("Firebase Error", f"Failed to initialize Firebase: {e}")
        exit()


def log_transaction(username, show_title, show_time, seats, status, price):
    """Logs a transaction with a unique ID."""
    try:
        transaction_id = str(uuid.uuid4())
        db.reference('transactions').push({
            "transaction_id": transaction_id,
            "Timestamp": datetime.now().strftime("%d-%m-%y %H:%M:%S"),
            "Username": username,
            "Movie Title": show_title,
            "Show Time": show_time,
            "Seats": ', '.join(map(str, seats)),
            "Payment Status": status,
            "Price": float(price)  # Store as number
        })
    except exceptions.FirebaseError as e:
        print(f"Error logging transaction: {e}")


def notify_user(username, message):
    """Pushes a notification to a user's Firebase notifications node."""
    try:
        db.reference(f'users/{username}/notifications').push({
            "message": message,
            "timestamp": datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        })
    except exceptions.FirebaseError as e:
        print(f"Error sending notification to {username}: {e}")


def validate_password(password):
    if len(password) < 8: return False, "Password must be at least 8 characters long."
    if len(password) > 32: return False, "Password must not exceed 32 characters."
    if not re.search(r"[A-Z]", password): return False, "Password must contain an uppercase letter."
    if not re.search(r"[a-z]", password): return False, "Password must contain a lowercase letter."
    if not re.search(r"\d", password): return False, "Password must contain a digit."
    if not re.search(r"[!@#$%^&*()-_=+{};:,<.>]", password): return False, "Password must contain a special character."
    return True, "Password is valid."


def signup_user(username, password):
    if not username or username.isspace():
        messagebox.showerror("Signup Failed", "Username cannot be empty.")
        return False
    if username.lower() == 'admin':
        messagebox.showerror("Signup Failed", "This username is reserved.")
        return False
    is_valid, message = validate_password(password)
    if not is_valid:
        messagebox.showerror("Signup Failed", message)
        return False
    try:
        if db.reference(f'users/{username}').get():
            messagebox.showerror("Signup Failed", "Username already exists.")
            return False
        hashed_pass = hash_password(password).decode('utf-8')
        db.reference(f'users/{username}').set({"password": hashed_pass, "role": "user"})
        messagebox.showinfo("Success", "Signup successful! You can now log in.")
        return True
    except exceptions.FirebaseError as e:
        messagebox.showerror("Database Error", f"An error occurred during signup: {e}")
        return False


def login_user(username, password):
    try:
        user_data = db.reference(f'users/{username}').get()
        if user_data and check_password(user_data.get("password").encode('utf-8'), password):
            return user_data.get("role", "user"), username
        return None, None
    except exceptions.FirebaseError as e:
        messagebox.showerror("Database Error", f"Could not verify login: {e}")
        return None, None


def update_dynamic_pricing(show_id):
    """Smooth dynamic pricing based on occupancy."""
    cleanup_past_shows()  # Clean up past shows before pricing
    try:
        show = db.reference(f'shows/{show_id}').get()
        if not show: return 0.0
        total = show.get("total_seats", 1)
        booked = len(show.get("booked_seats", {})) + len(show.get("pay_later_seats", {}))
        occupancy_percentage = (booked / total) * 100
        scaling_factor = 0.005
        return round(show.get("base_price", 0.0) * (1 + scaling_factor * occupancy_percentage), 2)
    except exceptions.FirebaseError:
        return 0.0


def get_global_unpaid_seats(username):
    """Count total unpaid seats across all shows."""
    cleanup_past_shows()  # Clean up past shows before counting
    try:
        total_unpaid = 0
        bookings = db.reference(f'users/{username}/bookings').get() or {}
        for booking in bookings.values():
            if booking.get('payment_status') == "Reserved":
                total_unpaid += len(booking.get('seats', []))
        return total_unpaid
    except exceptions.FirebaseError as e:
        print(f"Error counting unpaid seats: {e}")
        return 0


def book_ticket(username, show_id, seats, payment_option):
    """Books tickets with global unpaid limit and pay-later restrictions."""
    cleanup_past_shows()  # Clean up past shows before booking
    show_ref = db.reference(f'shows/{show_id}')

    def transaction_update(current_show_data):
        if current_show_data is None:
            return None
        booked_data = current_show_data.get('booked_seats', {})
        booked = booked_data.keys() if isinstance(booked_data, dict) else booked_data
        reserved_data = current_show_data.get('pay_later_seats', {})
        reserved = reserved_data.keys() if isinstance(reserved_data, dict) else reserved_data
        seats_set = set(seats)  # Prevent duplicates
        if len(seats_set) != len(seats):
            raise ValueError("Duplicate seat numbers provided.")
        for seat in seats_set:
            if seat in booked or seat in reserved:
                raise ValueError(f"Seat {seat} is already taken or reserved.")
        if payment_option == "pay_now":
            if 'booked_seats' not in current_show_data: current_show_data['booked_seats'] = {}
            for seat in seats_set: current_show_data['booked_seats'][seat] = True
        else:
            if 'pay_later_seats' not in current_show_data: current_show_data['pay_later_seats'] = {}
            for seat in seats_set: current_show_data['pay_later_seats'][seat] = username
        return current_show_data

    try:
        show = show_ref.get()
        if not show:
            messagebox.showerror("Booking Failed", "Show not found.")
            return False
        # Pay-later time restriction
        if payment_option == "pay_later":
            show_time = parse_show_time(show['show_time'], show_id, show.get('movie_title'), update_db=True)
            if show_time - datetime.now() < timedelta(minutes=PAY_LATER_DEADLINE_MINUTES):
                messagebox.showerror("Booking Failed", "Pay Later not allowed for shows starting within 30 minutes.")
                return False
            current_unpaid = get_global_unpaid_seats(username)
            if current_unpaid + len(seats) > 5:
                messagebox.showerror("Booking Failed", "Global unpaid reservation limit exceeded (max 5 seats).")
                return False

        result = show_ref.transaction(transaction_update)
        if result is None:
            messagebox.showerror("Booking Failed", "Show data could not be retrieved.")
            return False

        show = show_ref.get()
        if payment_option == "pay_now":
            price = update_dynamic_pricing(show_id) * len(seats)
            log_transaction(username, show['movie_title'], show['show_time'], seats, "Paid", price)
            details = {"payment_status": "Paid"}
        else:
            expiry_time = min(datetime.now() + timedelta(minutes=PAY_LATER_DEADLINE_MINUTES),
                              parse_show_time(show['show_time'], show_id, show.get('movie_title')) - timedelta(
                                  minutes=5))
            details = {"payment_status": "Reserved", "notified": False,
                       "expiry_time": expiry_time.strftime("%d-%m-%Y %H:%M")}

        db.reference(f'users/{username}/bookings').push({"show_id": show_id, "seats": list(seats), **details})
        return True
    except ValueError as e:
        messagebox.showerror("Booking Failed", str(e))
        return False
    except exceptions.FirebaseError as e:
        messagebox.showerror("Database Error", f"A conflict or database error occurred: {e}")
        return False


def cancel_ticket(username, booking_id):
    """Cancels a booking, logs to transaction history, and notifies user and admin."""
    cleanup_past_shows()  # Clean up past shows before cancellation
    try:
        booking_ref = db.reference(f'users/{username}/bookings/{booking_id}')
        booking = booking_ref.get()
        if not booking:
            messagebox.showerror("Cancellation Failed", "Booking not found.")
            return False

        show_ref = db.reference(f"shows/{booking['show_id']}")
        show = show_ref.get()
        if not show:
            messagebox.showerror("Cancellation Failed", "Show not found.")
            return False

        def transaction_update(current_show_data):
            if current_show_data is None: return None
            for seat in booking['seats']:
                if booking['payment_status'] == "Paid":
                    if 'booked_seats' in current_show_data and seat in current_show_data['booked_seats']:
                        del current_show_data['booked_seats'][seat]
                else:
                    if 'pay_later_seats' in current_show_data and seat in current_show_data['pay_later_seats']:
                        del current_show_data['pay_later_seats'][seat]
                if 'bids' not in current_show_data: current_show_data['bids'] = {}
                current_show_data['bids'][seat] = {"initial": True,
                                                   "created_at": datetime.now().strftime("%d-%m-%Y %H:%M")}
            return current_show_data

        result = show_ref.transaction(transaction_update)
        if result is None:
            messagebox.showerror("Cancellation Failed", "Show not found.")
            return False

        # Log cancellation to transaction history
        log_transaction(username, show['movie_title'], show['show_time'], booking['seats'], "Cancelled", 0.0)

        # Notify user and admin
        cancellation_message = f"Booking for '{show['movie_title']}' (Seats: {', '.join(booking['seats'])}) cancelled on {datetime.now().strftime('%d-%m-%Y %H:%M')}"
        notify_user(username, cancellation_message)
        notify_user('admin',
                    f"User {username} cancelled booking for '{show['movie_title']}' (Seats: {', '.join(booking['seats'])})")

        booking_ref.delete()
        return True
    except exceptions.FirebaseError as e:
        messagebox.showerror("Database Error", f"Could not cancel ticket: {e}")
        return False


def add_show(title, time, language, price, seats):
    """Adds a new show with input validation."""
    if not title or title.isspace():
        messagebox.showerror("Add Show Failed", "Title cannot be empty.")
        return False
    if not language or language.isspace():
        messagebox.showerror("Add Show Failed", "Language cannot be empty.")
        return False
    try:
        parsed_time = parse_show_time(time)
        if parsed_time < datetime.now():
            messagebox.showerror("Add Show Failed", "Cannot add a show in the past.")
            return False
        db.reference('shows').push({
            "movie_title": title,
            "show_time": parsed_time.strftime("%d-%m-%Y %H:%M"),
            "language": language,
            "base_price": float(price),
            "total_seats": int(seats)
        })
        return True
    except ValueError as e:
        messagebox.showerror("Add Show Failed", f"Invalid data format: {e}")
        return False
    except exceptions.FirebaseError as e:
        messagebox.showerror("Database Error", f"Could not add show: {e}")
        return False


def place_bet(username, show_id, seat, bid_amount):
    """Places a bid with self-outbid prevention and timeout."""
    cleanup_past_shows()  # Clean up past shows before placing bet
    show_ref = db.reference(f'shows/{show_id}')

    def transaction_update(current_show_data):
        if not current_show_data or seat not in current_show_data.get('bids', {}):
            raise ValueError("This seat is not available for betting.")
        bids = current_show_data['bids'][seat]
        actual_bids = {user: bid for user, bid in bids.items() if user != 'initial' and user != 'created_at'}
        if username in actual_bids:
            raise ValueError("You already have a bid for this seat.")
        highest_bid = max(actual_bids.values()) if actual_bids else 0
        if bid_amount < highest_bid + 1.0:
            raise ValueError(f"Bid must be at least ${highest_bid + 1.0:.2f}.")
        current_show_data['bids'][seat][username] = bid_amount
        current_show_data['bids'][seat]['created_at'] = datetime.now().strftime("%d-%m-%Y %H:%M")
        return current_show_data

    try:
        show_ref.transaction(transaction_update)
        messagebox.showinfo("Success", f"Your bid of ${bid_amount:.2f} was placed.")
        return True
    except ValueError as e:
        messagebox.showerror("Betting Failed", str(e))
        return False
    except exceptions.FirebaseError as e:
        messagebox.showerror("Database Error", f"Could not place bid: {e}")
        return False


def resolve_bid(show_id, seat):
    """Resolves a bid, checking for timeout."""
    cleanup_past_shows()  # Clean up past shows before resolving bid
    show_ref = db.reference(f'shows/{show_id}')
    try:
        show = show_ref.get()
        bids_for_seat = show.get('bids', {}).get(seat)
        if not show or not isinstance(bids_for_seat, dict): return None, None
        created_at = bids_for_seat.get('created_at')
        if created_at:
            bid_time = parse_show_time(created_at, show_id, show.get('movie_title'))
            if datetime.now() > bid_time + timedelta(hours=BID_TIMEOUT_HOURS):
                show_ref.child(f'bids/{seat}').delete()
                return None, None
        actual_bidders = {user: bid for user, bid in bids_for_seat.items() if
                          user != 'initial' and user != 'created_at'}
        if not actual_bidders:
            return None, None
        winner = max(actual_bidders, key=actual_bidders.get)
        winning_bid = actual_bidders[winner]
        show_ref.child(f'booked_seats/{seat}').set(True)
        show_ref.child(f'bids/{seat}').delete()
        db.reference(f'users/{winner}/bookings').push({
            "show_id": show_id, "seats": [seat], "payment_status": f"Paid (Won via Bid for ${winning_bid:.2f})"
        })
        log_transaction(winner, show['movie_title'], show['show_time'], [seat], "Paid (Bid Won)", winning_bid)
        return winner, winning_bid
    except exceptions.FirebaseError as e:
        messagebox.showerror("Database Error", f"Could not resolve bid: {e}")
        return None, None


def process_payment(username, booking_id):
    """Processes a 'Pay Later' booking and returns updated show data."""
    cleanup_past_shows()  # Clean up past shows before processing payment
    try:
        booking_ref = db.reference(f'users/{username}/bookings/{booking_id}')
        booking = booking_ref.get()
        if not booking:
            messagebox.showerror("Payment Failed", "Booking not found.")
            return False, None
        show_ref = db.reference(f"shows/{booking['show_id']}")
        show = show_ref.get()
        if not show:
            messagebox.showerror("Payment Failed", "Show not found.")
            return False, None
        show_time = parse_show_time(show['show_time'], show['show_id'], show.get('movie_title'), update_db=True)
        if show_time < datetime.now():
            messagebox.showerror("Payment Failed", "Cannot process payment for a past show.")
            return False, None

        def transaction_update(current_show_data):
            if current_show_data is None: return None
            for seat in booking['seats']:
                if 'pay_later_seats' in current_show_data and seat in current_show_data['pay_later_seats']:
                    del current_show_data['pay_later_seats'][seat]
                if 'booked_seats' not in current_show_data: current_show_data['booked_seats'] = {}
                current_show_data['booked_seats'][seat] = True
            return current_show_data

        result = show_ref.transaction(transaction_update)
        if result is None:
            messagebox.showerror("Payment Failed", "Show not found.")
            return False, None
        booking_ref.update({"payment_status": "Paid", "notified": None, "expiry_time": None})
        price = update_dynamic_pricing(booking['show_id']) * len(booking['seats'])
        log_transaction(username, show['movie_title'], show['show_time'], booking['seats'], "Paid (from Reserved)",
                        price)
        return True, show_ref.get()  # Return updated show data
    except exceptions.FirebaseError as e:
        messagebox.showerror("Database Error", f"Could not process payment: {e}")
        return False, None


def cleanup_past_shows():
    """Deletes past shows and fixes date formats."""
    print("Running cleanup of past shows...")
    now = datetime.now()
    print(f"Current system time is: {now.strftime('%d-%m-%Y %H:%M')}")
    try:
        all_shows = db.reference('shows').get() or {}
        shows_to_delete = []
        for show_id, show in all_shows.items():
            try:
                show_time_str = show.get('show_time')
                if not show_time_str:
                    print(f"Show ID {show_id} ('{show.get('movie_title')}') has no show_time. Skipping.")
                    continue
                show_time = parse_show_time(show_time_str, show_id, show.get('movie_title'), update_db=True)
                print(f"Checking show '{show.get('movie_title')}' with time {show_time_str}... ", end="")
                if show_time < now:
                    shows_to_delete.append((show_id, show.get('movie_title')))
                    print("Marked for DELETION.")
                else:
                    print("Is in the future. Keeping.")
            except ValueError as e:
                print(
                    f"\nWARNING: Could not parse time for show ID {show_id} ('{show.get('movie_title')}') with value '{show.get('show_time')}'. Error: {e}. Skipping.")
                continue
        if not shows_to_delete:
            print("No past shows found to clean up.")
            return
        print("\n--- Deleting Past Shows ---")
        for show_id, title in shows_to_delete:
            db.reference(f'shows/{show_id}').delete()
            print(f"Deleted past show: '{title}' (ID: {show_id})")
        print("--- Cleanup Complete ---")
    except exceptions.FirebaseError as e:
        print(f"An error occurred during show cleanup: {e}")


def check_pay_later_deadlines():
    """Checks and cancels expired pay-later bookings."""
    cleanup_past_shows()  # Clean up past shows before checking deadlines
    now = datetime.now()
    try:
        all_shows = db.reference('shows').get() or {}
        all_users = db.reference('users').get() or {}
        for username, user_data in all_users.items():
            if 'bookings' in user_data:
                for booking_id, booking in list(user_data['bookings'].items()):
                    if booking.get('payment_status') == "Reserved":
                        show = all_shows.get(booking['show_id'])
                        if not show:
                            continue
                        try:
                            expiry_time_str = booking.get('expiry_time', show['show_time'])
                            expiry_time = parse_show_time(expiry_time_str, booking['show_id'], show.get('movie_title'))
                            if now > expiry_time:
                                cancel_ticket(username, booking_id)
                                print(f"Cancelled expired booking {booking_id} for {username}")
                            elif now > (parse_show_time(show['show_time'], booking['show_id'],
                                                        show.get('movie_title')) - timedelta(
                                    minutes=PAY_LATER_NOTIFICATION_MINUTES)) and not booking.get("notified"):
                                print(
                                    f"REMINDER: Payment is due soon for {username}'s booking for '{show['movie_title']}'.")
                                notify_user(username,
                                            f"Payment due soon for '{show['movie_title']}' (Seats: {', '.join(booking['seats'])})")
                                db.reference(f'users/{username}/bookings/{booking_id}').update({"notified": True})
                        except ValueError:
                            continue
    except exceptions.FirebaseError as e:
        print(f"Could not check deadlines: {e}")
    app.after(60000, check_pay_later_deadlines)


# --- GUI Classes ---
class NeonButton(tk.Button):
    def __init__(self, master, **kw):
        super().__init__(master=master, **kw)
        self.config(font=FONT_BOLD, bg=BG_COLOR, fg=NEON_RED, activebackground=NEON_RED_HOVER,
                    activeforeground=FG_COLOR, relief="flat", borderwidth=2, highlightthickness=2,
                    highlightbackground=NEON_RED, highlightcolor=NEON_RED)
        self.bind("<Enter>", lambda e: self.config(fg=NEON_RED_HOVER, highlightbackground=NEON_RED_HOVER))
        self.bind("<Leave>", lambda e: self.config(fg=NEON_RED, highlightbackground=NEON_RED))


class ValidatingEntry(tk.Entry):
    def __init__(self, master, **kw):
        super().__init__(master=master, **kw)
        self.config(font=FONT_NORMAL, bg=ENTRY_BG, fg=FG_COLOR, insertbackground=FG_COLOR,
                    relief="flat", highlightthickness=2, width=30)
        self.reset_style()
        self.bind("<Key>", lambda e: self.reset_style())

    def set_valid(self): self.config(highlightbackground=VALID_GREEN, highlightcolor=VALID_GREEN)

    def set_invalid(self): self.config(highlightbackground=ERROR_RED, highlightcolor=ERROR_RED)

    def reset_style(self): self.config(highlightbackground=NEON_RED, highlightcolor=NEON_RED)


class MovieTicketBookingSystem(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.title("Movie Ticket Booking System (Firebase Edition)")
        self.geometry("1000x700");
        self.configure(bg=BG_COLOR)
        self.current_session = {'username': None, 'role': None}
        container = tk.Frame(self, bg=BG_COLOR)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1);
        container.grid_columnconfigure(0, weight=1)
        self.frames = {}
        for F in (MainMenu, LoginScreen, SignupScreen, UserMenu, AdminMenu, ShowListingsScreen,
                  BookingScreen, MyBookingsScreen, CancellationScreen, BettingScreen, ManageShowsScreen,
                  ResolveBidsScreen, ViewAllBookingsScreen, TransactionHistoryScreen, NotificationsScreen):
            frame = F(parent=container, controller=self)
            self.frames[F.__name__] = frame;
            frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame("MainMenu")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def show_frame(self, p):
        frame = self.frames[p]
        frame.event_generate("<<ShowFrame>>")
        frame.tkraise()

    def logged_in(self, u, r):
        self.current_session = {'username': u, 'role': r}
        self.show_frame("AdminMenu" if r == 'admin' else "UserMenu")

    def logout(self):
        self.current_session = {'username': None, 'role': None}
        self.show_frame("MainMenu")

    def on_closing(self):
        for frame in self.frames.values():
            frame.destroy()
        self.destroy()


class MainMenu(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg=BG_COLOR)
        content = tk.Frame(self, bg=BG_COLOR);
        content.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(content, text="Welcome to the Cineplex", font=FONT_LARGE, bg=BG_COLOR, fg=FG_COLOR).pack(pady=40)
        NeonButton(content, text="Login", command=lambda: controller.show_frame("LoginScreen")).pack(pady=10, ipadx=10,
                                                                                                     ipady=5)
        NeonButton(content, text="Signup", command=lambda: controller.show_frame("SignupScreen")).pack(pady=10,
                                                                                                       ipadx=10,
                                                                                                       ipady=5)
        NeonButton(content, text="Show Listings", command=lambda: controller.show_frame("ShowListingsScreen")).pack(
            pady=10, ipadx=10, ipady=5)
        NeonButton(content, text="Exit", command=controller.quit).pack(pady=10, ipadx=10, ipady=5)


class LoginScreen(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg=BG_COLOR)
        self.controller = controller
        content = tk.Frame(self, bg=BG_COLOR);
        content.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(content, text="User Login", font=FONT_MEDIUM, bg=BG_COLOR, fg=FG_COLOR).pack(pady=20)
        tk.Label(content, text="Username", font=FONT_NORMAL, bg=BG_COLOR, fg=FG_COLOR).pack(pady=(10, 0))
        self.username = ValidatingEntry(content);
        self.username.pack()
        tk.Label(content, text="Password", font=FONT_NORMAL, bg=BG_COLOR, fg=FG_COLOR).pack(pady=(10, 0))
        self.password = ValidatingEntry(content, show="*");
        self.password.pack()
        self.error_label = tk.Label(content, text="", font=FONT_NORMAL, bg=BG_COLOR, fg=ERROR_RED);
        self.error_label.pack(pady=10)
        NeonButton(content, text="Login", command=self.login).pack(pady=20, ipadx=10, ipady=5)
        NeonButton(content, text="Back", command=lambda: controller.show_frame("MainMenu")).pack(ipadx=10, ipady=5)
        self.bind("<<ShowFrame>>", self.on_show_frame)

    def on_show_frame(self, event=None):
        self.username.delete(0, tk.END);
        self.password.delete(0, tk.END)
        self.username.reset_style();
        self.password.reset_style();
        self.error_label.config(text="")

    def login(self):
        username = self.username.get().strip()
        if not username:
            self.error_label.config(text="Username cannot be empty.")
            self.username.set_invalid()
            return
        role, user = login_user(username, self.password.get())
        if role and user:
            self.controller.logged_in(user, role)
        else:
            self.username.set_invalid();
            self.password.set_invalid()
            self.error_label.config(text="Invalid credentials.")


class SignupScreen(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg=BG_COLOR)
        self.controller = controller
        content = tk.Frame(self, bg=BG_COLOR);
        content.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(content, text="Create Account", font=FONT_MEDIUM, bg=BG_COLOR, fg=FG_COLOR).pack(pady=20)
        tk.Label(content, text="Username", font=FONT_NORMAL, bg=BG_COLOR, fg=FG_COLOR).pack(pady=(10, 0))
        self.username = ValidatingEntry(content);
        self.username.pack()
        tk.Label(content, text="Password", font=FONT_NORMAL, bg=BG_COLOR, fg=FG_COLOR).pack(pady=(10, 0))
        self.password = ValidatingEntry(content, show="*");
        self.password.pack()
        NeonButton(content, text="Signup", command=self.signup).pack(pady=20, ipadx=10, ipady=5)
        NeonButton(content, text="Back", command=lambda: controller.show_frame("MainMenu")).pack(ipadx=10, ipady=5)

    def signup(self):
        if signup_user(self.username.get().strip(), self.password.get()):
            self.controller.show_frame("LoginScreen")


class UserMenu(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg=BG_COLOR)
        self.controller = controller
        content = tk.Frame(self, bg=BG_COLOR);
        content.place(relx=0.5, rely=0.5, anchor="center")
        self.welcome = tk.Label(content, text="", font=FONT_MEDIUM, bg=BG_COLOR, fg=FG_COLOR);
        self.welcome.pack(pady=40)
        NeonButton(content, text="Book Ticket", command=lambda: controller.show_frame("ShowListingsScreen")).pack(
            pady=10, ipadx=10, ipady=5)
        NeonButton(content, text="My Bookings", command=lambda: controller.show_frame("MyBookingsScreen")).pack(pady=10,
                                                                                                                ipadx=10,
                                                                                                                ipady=5)
        NeonButton(content, text="Cancel Booking", command=lambda: controller.show_frame("CancellationScreen")).pack(
            pady=10, ipadx=10, ipady=5)
        NeonButton(content, text="Join Betting", command=lambda: controller.show_frame("BettingScreen")).pack(pady=10,
                                                                                                              ipadx=10,
                                                                                                              ipady=5)
        NeonButton(content, text="View Notifications",
                   command=lambda: controller.show_frame("NotificationsScreen")).pack(pady=10, ipadx=10, ipady=5)
        NeonButton(content, text="Logout", command=controller.logout).pack(pady=20, ipadx=10, ipady=5)
        self.bind("<<ShowFrame>>", self.on_show_frame)

    def on_show_frame(self, e=None):
        self.welcome.config(text=f"Welcome, {self.controller.current_session['username']}!")
        for child in self.winfo_children():
            child.unbind_all("<Button-1>")


class AdminMenu(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg=BG_COLOR)
        self.controller = controller
        content = tk.Frame(self, bg=BG_COLOR);
        content.place(relx=0.5, rely=0.5, anchor="center")
        self.welcome = tk.Label(content, text="", font=FONT_MEDIUM, bg=BG_COLOR, fg=FG_COLOR);
        self.welcome.pack(pady=40)
        NeonButton(content, text="Manage Shows", command=lambda: controller.show_frame("ManageShowsScreen")).pack(
            pady=10, ipadx=10, ipady=5)
        NeonButton(content, text="View All Bookings",
                   command=lambda: controller.show_frame("ViewAllBookingsScreen")).pack(pady=10, ipadx=10, ipady=5)
        NeonButton(content, text="Resolve Bids", command=lambda: controller.show_frame("ResolveBidsScreen")).pack(
            pady=10, ipadx=10, ipady=5)
        NeonButton(content, text="Transaction History",
                   command=lambda: controller.show_frame("TransactionHistoryScreen")).pack(pady=10, ipadx=10, ipady=5)
        NeonButton(content, text="View Notifications",
                   command=lambda: controller.show_frame("NotificationsScreen")).pack(pady=10, ipadx=10, ipady=5)
        NeonButton(content, text="Logout", command=controller.logout).pack(pady=20, ipadx=10, ipady=5)
        self.bind("<<ShowFrame>>", self.on_show_frame)

    def on_show_frame(self, e=None):
        self.welcome.config(text=f"Admin Panel: {self.controller.current_session['username']}")


class ShowListingsScreen(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg=BG_COLOR)
        self.controller = controller;
        self.show_map = {}
        tk.Label(self, text="Available Shows", font=FONT_MEDIUM, bg=BG_COLOR, fg=FG_COLOR).pack(pady=20)
        style = ttk.Style()
        style.configure("Treeview", background=LISTBOX_BG, foreground=FG_COLOR, fieldbackground=LISTBOX_BG,
                        rowheight=25, font=FONT_NORMAL)
        style.configure("Treeview.Heading", background=NEON_RED, foreground=FG_COLOR, font=FONT_BOLD)
        tree_frame = tk.Frame(self, bg=BG_COLOR);
        tree_frame.pack(pady=10, padx=20, fill="x", expand=True)
        self.tree = ttk.Treeview(tree_frame, columns=('ID', 'Title', 'Time', 'Price', 'Seats'), show='headings')
        for col in ('ID', 'Title', 'Time', 'Price', 'Seats'): self.tree.heading(col, text=col)
        self.tree.column('ID', width=150);
        self.tree.column('Title', width=250);
        self.tree.column('Time', width=150)
        self.tree.pack(side="left", fill="both", expand=True)
        button_frame = tk.Frame(self, bg=BG_COLOR);
        button_frame.pack(pady=20)
        self.book_button = NeonButton(button_frame, text="Book Selected Show", command=self.book_selected)
        NeonButton(button_frame, text="Back", command=self.go_back).pack(side="left", padx=10, ipadx=10, ipady=5)
        self.bind("<<ShowFrame>>", self.on_show_frame)

    def on_show_frame(self, event=None):
        self.populate_shows()
        if self.controller.current_session.get('role') == 'user':
            self.book_button.pack(side="left", padx=10, ipadx=10, ipady=5)
        else:
            self.book_button.pack_forget()

    def go_back(self):
        role = self.controller.current_session.get('role')
        frame = "AdminMenu" if role == 'admin' else "UserMenu" if role == 'user' else "MainMenu"
        self.controller.show_frame(frame)

    def populate_shows(self):
        cleanup_past_shows()  # Clean up past shows before populating
        self.show_map.clear()
        for i in self.tree.get_children(): self.tree.delete(i)
        try:
            all_shows = db.reference('shows').get()
            if not all_shows: return
            for show_id, show in all_shows.items():
                try:
                    parse_show_time(show.get('show_time'), show_id, show.get('movie_title'), update_db=True)
                    price = update_dynamic_pricing(show_id)
                    available = show.get("total_seats", 0) - len(show.get("booked_seats", {})) - len(
                        show.get("pay_later_seats", {}))
                    item_id = self.tree.insert("", "end", values=(
                    show_id, show.get('movie_title'), show.get('show_time'), f"${price:.2f}", available))
                    self.show_map[item_id] = show_id
                except ValueError as e:
                    print(f"Skipping show {show_id} due to invalid time format: {e}")
        except exceptions.FirebaseError as e:
            messagebox.showerror("Database Error", f"Could not load shows: {e}")

    def book_selected(self):
        if not self.tree.focus(): return
        show_id = self.show_map.get(self.tree.focus())
        if show_id:
            self.controller.frames["BookingScreen"].setup_booking(show_id)
            self.controller.show_frame("BookingScreen")


class BookingScreen(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg=BG_COLOR);
        self.controller = controller;
        self.show_id = None
        self.title_label = tk.Label(self, font=FONT_MEDIUM, bg=BG_COLOR, fg=FG_COLOR);
        self.title_label.pack(pady=10)
        self.seats_frame = tk.Frame(self, bg=BG_COLOR);
        self.seats_frame.pack(pady=10)
        input_frame = tk.Frame(self, bg=BG_COLOR);
        input_frame.pack(pady=10)
        tk.Label(input_frame, text="Enter seat numbers (e.g., 1,5,12):", font=FONT_NORMAL, bg=BG_COLOR,
                 fg=FG_COLOR).pack(pady=5)
        self.seat_entry = ValidatingEntry(input_frame, width=50);
        self.seat_entry.pack()
        self.payment_var = tk.StringVar(value="pay_now")
        s = {"bg": BG_COLOR, "fg": FG_COLOR, "selectcolor": BG_COLOR, "font": FONT_NORMAL}
        radio_frame = tk.Frame(self, bg=BG_COLOR);
        radio_frame.pack(pady=10)
        self.pay_now_radio = tk.Radiobutton(radio_frame, text="Pay Now", variable=self.payment_var, value="pay_now",
                                            **s)
        self.pay_now_radio.pack(side="left")
        self.pay_later_radio = tk.Radiobutton(radio_frame, text="Pay Later", variable=self.payment_var,
                                              value="pay_later", **s)
        self.pay_later_radio.pack(side="left")
        button_frame = tk.Frame(self, bg=BG_COLOR);
        button_frame.pack(pady=20)
        NeonButton(button_frame, text="Confirm Booking", command=self.confirm_booking).pack(side="left", padx=10,
                                                                                            ipadx=10)
        NeonButton(button_frame, text="Refresh Seats", command=self.refresh_seats).pack(side="left", padx=10, ipadx=10)
        NeonButton(button_frame, text="Back", command=lambda: controller.show_frame("ShowListingsScreen")).pack(
            side="left", padx=10, ipadx=10)
        self.bind("<<ShowFrame>>", self.on_show_frame)

    def on_show_frame(self, event=None):
        self.seat_entry.delete(0, tk.END)
        self.payment_var.set("pay_now")

    def setup_booking(self, show_id):
        self.show_id = show_id
        self.refresh_seats()

    def refresh_seats(self):
        if not self.show_id:
            return
        cleanup_past_shows()  # Clean up past shows before refreshing seats
        try:
            show = db.reference(f'shows/{self.show_id}').get()
            if not show:
                messagebox.showerror("Error", "Show not found.")
                return
            self.current_show_data = show
            self.title_label.config(text=f"Booking for: {show.get('movie_title')}")
            show_time = parse_show_time(show.get('show_time'), self.show_id, show.get('movie_title'), update_db=True)
            if show_time - datetime.now() < timedelta(minutes=PAY_LATER_DEADLINE_MINUTES):
                self.pay_later_radio.config(state="disabled")
                self.payment_var.set("pay_now")
            else:
                self.pay_later_radio.config(state="normal")
            self.display_seats(show)
        except ValueError as e:
            messagebox.showerror("Database Error", f"Invalid show time format: {e}")
            self.controller.show_frame("ShowListingsScreen")
        except exceptions.FirebaseError as e:
            messagebox.showerror("Database Error", f"Could not load show details: {e}")
            self.controller.show_frame("ShowListingsScreen")

    def display_seats(self, show):
        for widget in self.seats_frame.winfo_children(): widget.destroy()
        booked_data = show.get('booked_seats', {})
        booked = set(booked_data.keys()) if isinstance(booked_data, dict) else set(booked_data)
        reserved_data = show.get('pay_later_seats', {})
        reserved = set(reserved_data.keys()) if isinstance(reserved_data, dict) else set(reserved_data)
        cols = 10;
        seat_grid = tk.Frame(self.seats_frame, bg=BG_COLOR);
        seat_grid.pack()
        for i in range(1, show.get('total_seats', 0) + 1):
            s = str(i)
            color = "red" if s in booked else "orange" if s in reserved else VALID_GREEN
            tk.Label(seat_grid, text=s, bg=color, fg="white", font=("Consolas", 10, "bold"), width=4,
                     relief="solid").grid(row=(i - 1) // cols, column=(i - 1) % cols, padx=2, pady=2)

    def confirm_booking(self):
        seats_str = self.seat_entry.get().strip().split(',')
        if not seats_str or not seats_str[0]:
            messagebox.showerror("Error", "Please enter at least one seat number.")
            self.seat_entry.set_invalid()
            return
        try:
            seats_int = [int(s.strip()) for s in seats_str if s.strip()]
            if not seats_int:
                messagebox.showerror("Error", "Invalid input. Please enter numbers only.")
                self.seat_entry.set_invalid()
                return
        except ValueError:
            messagebox.showerror("Error", "Invalid input. Please enter numbers only, separated by commas.")
            self.seat_entry.set_invalid()
            return
        total_seats = self.current_show_data.get("total_seats", 0)
        for seat in seats_int:
            if not (1 <= seat <= total_seats):
                messagebox.showerror("Error",
                                     f"Invalid seat number: {seat}. Seats must be between 1 and {total_seats}.")
                self.seat_entry.set_invalid()
                return
        seats_to_book = [str(s) for s in seats_int]
        if book_ticket(self.controller.current_session['username'], self.show_id, seats_to_book,
                       self.payment_var.get()):
            messagebox.showinfo("Success", "Tickets booked successfully!")
            self.refresh_seats()
            self.seat_entry.delete(0, tk.END)


class MyBookingsScreen(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg=BG_COLOR)
        self.controller = controller;
        self.after_id = None;
        self.timers = []
        tk.Label(self, text="My Bookings", font=FONT_MEDIUM, bg=BG_COLOR, fg=FG_COLOR).pack(pady=20)
        self.bookings_frame = tk.Frame(self, bg=BG_COLOR);
        self.bookings_frame.pack(pady=10, padx=20, fill="both", expand=True)
        button_frame = tk.Frame(self, bg=BG_COLOR);
        button_frame.pack(pady=20)
        NeonButton(button_frame, text="Refresh Bookings", command=self.refresh_bookings).pack(side="left", padx=10,
                                                                                              ipadx=10)
        NeonButton(button_frame, text="Back", command=lambda: controller.show_frame("UserMenu")).pack(side="left",
                                                                                                      padx=10, ipadx=10)
        self.bind("<<ShowFrame>>", self.on_show_frame)

    def on_show_frame(self, event=None):
        self.refresh_bookings()

    def refresh_bookings(self):
        if self.after_id:
            self.after_cancel(self.after_id)
            self.after_id = None
        for widget in self.bookings_frame.winfo_children(): widget.destroy()
        self.timers.clear()
        self.populate_bookings()
        if self.timers:
            self.update_timers()

    def populate_bookings(self):
        cleanup_past_shows()  # Clean up past shows before populating bookings
        username = self.controller.current_session['username']
        try:
            all_bookings = db.reference(f'users/{username}/bookings').get() or {}
            all_shows = db.reference('shows').get() or {}
            for b_id, b in all_bookings.items():
                show = all_shows.get(b['show_id'])
                if not show:
                    continue
                entry = tk.Frame(self.bookings_frame, bg=ENTRY_BG, highlightbackground=NEON_RED, highlightthickness=1)
                entry.pack(fill="x", pady=5, padx=5, ipady=5)
                tk.Label(entry, text=f"{show['movie_title']} | Seats: {', '.join(b['seats'])}", anchor="w", bg=ENTRY_BG,
                         fg=FG_COLOR, font=FONT_NORMAL).pack(side="left", padx=10)
                if b.get('payment_status') == "Reserved":
                    try:
                        expiry_time_str = b.get('expiry_time', show['show_time'])
                        expiry_time = parse_show_time(expiry_time_str, b['show_id'], show.get('movie_title'))
                        pay_button = NeonButton(entry, text="Pay Now",
                                                command=lambda bid=b_id: self.pay_for_booking(bid))
                        pay_button.pack(side="right", padx=10)
                        timer_label = tk.Label(entry, text="", fg=ERROR_RED, bg=ENTRY_BG, font=FONT_BOLD);
                        timer_label.pack(side="right", padx=10)
                        self.timers.append({"label": timer_label, "deadline": expiry_time, "button": pay_button})
                    except ValueError:
                        tk.Label(entry, text="Status: Reserved (Time Error)", anchor="e", bg=ENTRY_BG, fg=ERROR_RED,
                                 font=FONT_BOLD).pack(side="right", padx=10)
                else:
                    tk.Label(entry, text=f"Status: {b.get('payment_status', 'N/A')}", anchor="e", bg=ENTRY_BG,
                             fg=VALID_GREEN, font=FONT_BOLD).pack(side="right", padx=10)
        except exceptions.FirebaseError as e:
            messagebox.showerror("Database Error", f"Could not load bookings: {e}")

    def update_timers(self):
        for timer in self.timers:
            remaining = timer["deadline"] - datetime.now()
            if remaining.total_seconds() > 0:
                h, rem = divmod(int(remaining.total_seconds()), 3600);
                m, s = divmod(rem, 60)
                timer["label"].config(text=f"Time left: {h:02}:{m:02}:{s:02}")
            else:
                timer["label"].config(text="Deadline Passed", fg="gray");
                timer["button"].config(state="disabled")
        self.after_id = self.after(1000, self.update_timers)

    def pay_for_booking(self, booking_id):
        success, updated_show = process_payment(self.controller.current_session['username'], booking_id)
        if success:
            messagebox.showinfo("Success", "Payment successful!")
            self.refresh_bookings()
            if updated_show and self.controller.frames["BookingScreen"].show_id == updated_show.get('show_id'):
                self.controller.frames["BookingScreen"].refresh_seats()
        else:
            messagebox.showerror("Error", "Failed to process payment.")


class CancellationScreen(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg=BG_COLOR)
        self.controller = controller;
        self.booking_map = {}
        tk.Label(self, text="Cancel Booking", font=FONT_MEDIUM, bg=BG_COLOR, fg=FG_COLOR).pack(pady=20)
        self.listbox = tk.Listbox(self, width=100, height=20, bg=LISTBOX_BG, fg=FG_COLOR, font=FONT_NORMAL)
        self.listbox.pack(pady=10, padx=20)
        button_frame = tk.Frame(self, bg=BG_COLOR);
        button_frame.pack(pady=20)
        NeonButton(button_frame, text="Cancel Selected", command=self.cancel_selected).pack(side="left", padx=10,
                                                                                            ipadx=10)
        NeonButton(button_frame, text="Back", command=lambda: controller.show_frame("UserMenu")).pack(side="left",
                                                                                                      padx=10, ipadx=10)
        self.bind("<<ShowFrame>>", self.on_show_frame)

    def on_show_frame(self, event=None):
        cleanup_past_shows()  # Clean up past shows before displaying bookings
        self.listbox.delete(0, tk.END);
        self.booking_map.clear()
        username = self.controller.current_session['username']
        try:
            all_bookings = db.reference(f'users/{username}/bookings').get() or {}
            all_shows = db.reference('shows').get() or {}
            for b_id, b in all_bookings.items():
                show = all_shows.get(b['show_id'])
                if show:
                    self.listbox.insert(tk.END,
                                        f"{show['movie_title']} | Seats: {', '.join(b['seats'])} | Status: {b['payment_status']}")
                    self.booking_map[self.listbox.size() - 1] = b_id
        except exceptions.FirebaseError as e:
            messagebox.showerror("Database Error", f"Could not load bookings: {e}")

    def cancel_selected(self):
        if not self.listbox.curselection():
            messagebox.showerror("Error", "No booking selected.")
            return
        booking_id = self.booking_map.get(self.listbox.curselection()[0])
        if booking_id and cancel_ticket(self.controller.current_session['username'], booking_id):
            messagebox.showinfo("Success", "Booking cancelled.")
            self.on_show_frame()
            # Refresh seats if on BookingScreen
            if self.controller.frames["BookingScreen"].show_id:
                self.controller.frames["BookingScreen"].refresh_seats()


class BettingScreen(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg=BG_COLOR)
        self.controller = controller;
        self.bet_map = {}
        tk.Label(self, text="Bet on Cancelled Seats", font=FONT_MEDIUM, bg=BG_COLOR, fg=FG_COLOR).pack(pady=20)
        self.listbox = tk.Listbox(self, width=100, height=20, bg=LISTBOX_BG, fg=FG_COLOR, font=FONT_NORMAL)
        self.listbox.pack(pady=10, padx=20)
        button_frame = tk.Frame(self, bg=BG_COLOR);
        button_frame.pack(pady=20)
        NeonButton(button_frame, text="Place Bid on Selected", command=self.place_bid).pack(side="left", padx=10,
                                                                                            ipadx=10)
        NeonButton(button_frame, text="Back", command=lambda: controller.show_frame("UserMenu")).pack(side="left",
                                                                                                      padx=10, ipadx=10)
        self.bind("<<ShowFrame>>", self.on_show_frame)

    def on_show_frame(self, event=None):
        cleanup_past_shows()  # Clean up past shows before displaying bets
        self.listbox.delete(0, tk.END);
        self.bet_map.clear()
        try:
            all_shows = db.reference('shows').get() or {}
            for show_id, show in all_shows.items():
                if 'bids' in show:
                    for seat, bids_data in show['bids'].items():
                        if isinstance(bids_data, dict):
                            actual_bids = {user: bid for user, bid in bids_data.items() if
                                           user != 'initial' and user != 'created_at'}
                            highest_bid = max(actual_bids.values()) if actual_bids else 0.0
                            self.listbox.insert(tk.END,
                                                f"Seat {seat}, {show['movie_title']} | Highest Bid: ${highest_bid:.2f}")
                            self.bet_map[self.listbox.size() - 1] = (show_id, seat)
        except exceptions.FirebaseError as e:
            messagebox.showerror("Database Error", f"Could not load betting data: {e}")

    def place_bid(self):
        if not self.listbox.curselection():
            messagebox.showerror("Error", "No seat selected.")
            return
        show_id, seat = self.bet_map.get(self.listbox.curselection()[0])
        bid = simpledialog.askfloat("Place Bid", "Enter bid amount:", parent=self, minvalue=0.01)
        if bid is not None:
            if place_bet(self.controller.current_session['username'], show_id, seat, bid):
                self.on_show_frame()


class ManageShowsScreen(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg=BG_COLOR)
        self.controller = controller;
        self.show_map = {}
        tk.Label(self, text="Manage Shows", font=FONT_MEDIUM, bg=BG_COLOR, fg=FG_COLOR).pack(pady=20)
        self.listbox = tk.Listbox(self, width=100, height=20, bg=LISTBOX_BG, fg=FG_COLOR, font=FONT_NORMAL)
        self.listbox.pack(pady=10, padx=20)
        button_frame = tk.Frame(self, bg=BG_COLOR);
        button_frame.pack(pady=20)
        NeonButton(button_frame, text="Add New", command=self.add_new).pack(side=tk.LEFT, padx=10, ipadx=10)
        NeonButton(button_frame, text="Remove Selected", command=self.remove_selected).pack(side=tk.LEFT, padx=10,
                                                                                            ipadx=10)
        NeonButton(button_frame, text="Back", command=lambda: controller.show_frame("AdminMenu")).pack(side=tk.RIGHT,
                                                                                                       padx=10,
                                                                                                       ipadx=10)
        self.bind("<<ShowFrame>>", self.on_show_frame)

    def on_show_frame(self, event=None):
        cleanup_past_shows()  # Clean up past shows before managing shows
        self.listbox.delete(0, tk.END);
        self.show_map.clear()
        try:
            for show_id, show in (db.reference('shows').get() or {}).items():
                try:
                    parse_show_time(show.get('show_time'), show_id, show.get('movie_title'), update_db=True)
                    self.listbox.insert(tk.END, f"{show['movie_title']} ({show['show_time']})")
                    self.show_map[self.listbox.size() - 1] = show_id
                except ValueError as e:
                    print(f"Skipping show {show_id} due to invalid time format: {e}")
        except exceptions.FirebaseError as e:
            messagebox.showerror("Database Error", f"Could not load shows: {e}")

    def remove_selected(self):
        if not self.listbox.curselection():
            messagebox.showerror("Error", "No show selected.")
            return
        show_id = self.show_map.get(self.listbox.curselection()[0])
        if show_id and messagebox.askyesno("Confirm", "Remove this show?"):
            try:
                db.reference(f'shows/{show_id}').delete()
                messagebox.showinfo("Success", "Show removed.")
                self.on_show_frame()
            except exceptions.FirebaseError as e:
                messagebox.showerror("Database Error", f"Could not remove show: {e}")

    def add_new(self):
        dialog = Toplevel(self, bg=BG_COLOR);
        dialog.title("Add New Show");
        dialog.geometry("400x400")
        entries = {}
        for field in ["Title", "Time (DD-MM-YYYY HH:MM)", "Language", "Base Price", "Total Seats"]:
            tk.Label(dialog, text=field + ":", bg=BG_COLOR, fg=FG_COLOR, font=FONT_NORMAL).pack(pady=(10, 0))
            entry = ValidatingEntry(dialog);
            entry.pack()
            entries[field.split(' ')[0]] = entry

        def submit():
            try:
                title = entries['Title'].get().strip()
                language = entries['Language'].get().strip()
                price = float(entries['Base'].get())
                seats = int(entries['Total'].get())
                if not title or not language:
                    raise ValueError("Title and Language cannot be empty.")
                if price <= 0 or seats <= 0:
                    raise ValueError("Price and seats must be positive.")
                if add_show(title, entries['Time'].get(), language, price, seats):
                    messagebox.showinfo("Success", "Show added.", parent=dialog)
                    self.on_show_frame()
                    dialog.destroy()
            except ValueError as e:
                messagebox.showerror("Error", f"Invalid input: {e}", parent=dialog)

        NeonButton(dialog, text="Submit", command=submit).pack(pady=20, ipadx=10, ipady=5)


class ResolveBidsScreen(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg=BG_COLOR)
        self.controller = controller;
        self.bid_map = {}
        tk.Label(self, text="Resolve Active Bids", font=FONT_MEDIUM, bg=BG_COLOR, fg=FG_COLOR).pack(pady=20)
        self.listbox = tk.Listbox(self, width=100, height=20, bg=LISTBOX_BG, fg=FG_COLOR, font=FONT_NORMAL)
        self.listbox.pack(pady=10, padx=20)
        button_frame = tk.Frame(self, bg=BG_COLOR);
        button_frame.pack(pady=20)
        NeonButton(button_frame, text="Resolve Selected Bid", command=self.resolve_selected).pack(side="left", padx=10,
                                                                                                  ipadx=10)
        NeonButton(button_frame, text="Back", command=lambda: controller.show_frame("AdminMenu")).pack(side="left",
                                                                                                       padx=10,
                                                                                                       ipadx=10)
        self.bind("<<ShowFrame>>", self.on_show_frame)

    def on_show_frame(self, event=None):
        cleanup_past_shows()  # Clean up past shows before resolving bids
        self.listbox.delete(0, tk.END);
        self.bid_map.clear()
        try:
            all_shows = db.reference('shows').get() or {}
            for show_id, show in all_shows.items():
                if 'bids' in show:
                    for seat, bids_data in show['bids'].items():
                        if isinstance(bids_data, dict):
                            actual_bidders = {user: bid for user, bid in bids_data.items() if
                                              user != 'initial' and user != 'created_at'}
                            if actual_bidders:
                                highest_bid = max(actual_bidders.values())
                                self.listbox.insert(tk.END,
                                                    f"Seat {seat}, {show['movie_title']} | Highest Bid: ${highest_bid:.2f} | Bidders: {len(actual_bidders)}")
                            else:
                                self.listbox.insert(tk.END,
                                                    f"Seat {seat}, {show['movie_title']} | Highest Bid: $0.00 | Bidders: 0")
                            self.bid_map[self.listbox.size() - 1] = (show_id, seat)
        except exceptions.FirebaseError as e:
            messagebox.showerror("Database Error", f"Could not load bids: {e}")

    def resolve_selected(self):
        if not self.listbox.curselection():
            messagebox.showerror("Error", "No bid selected.")
            return
        show_id, seat = self.bid_map.get(self.listbox.curselection()[0])
        winner, bid = resolve_bid(show_id, seat)
        if winner:
            messagebox.showinfo("Bid Resolved", f"Seat awarded to {winner} for ${bid:.2f}.")
            self.on_show_frame()
        else:
            messagebox.showinfo("Bid Not Resolved",
                                "This bid cannot be resolved as no one has placed a bet yet or the bid has expired.")


class ViewAllBookingsScreen(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg=BG_COLOR)
        self.controller = controller
        tk.Label(self, text="All System Bookings", font=FONT_MEDIUM, bg=BG_COLOR, fg=FG_COLOR).pack(pady=20)
        self.listbox = tk.Listbox(self, width=110, height=25, bg=LISTBOX_BG, fg=FG_COLOR, font=FONT_NORMAL)
        self.listbox.pack(pady=10, padx=20)
        button_frame = tk.Frame(self, bg=BG_COLOR);
        button_frame.pack(pady=20)
        NeonButton(button_frame, text="Back", command=lambda: controller.show_frame("AdminMenu")).pack(side="left",
                                                                                                       padx=10,
                                                                                                       ipadx=10)
        self.bind("<<ShowFrame>>", self.on_show_frame)

    def on_show_frame(self, event=None):
        cleanup_past_shows()  # Clean up past shows before viewing bookings
        self.listbox.delete(0, tk.END)
        try:
            all_users = db.reference('users').get() or {};
            all_shows = db.reference('shows').get() or {}
            for username, data in all_users.items():
                if 'bookings' in data:
                    for booking_id, booking in data['bookings'].items():
                        show_id = booking.get('show_id')
                        show = all_shows.get(show_id)
                        if show:
                            try:
                                parse_show_time(show['show_time'], show_id, show.get('movie_title'), update_db=True)
                                self.listbox.insert(tk.END,
                                                    f"User: {username} | Movie: {show['movie_title']} | Seats: {', '.join(booking['seats'])} | Status: {booking['payment_status']}")
                            except ValueError as e:
                                print(
                                    f"Skipping booking {booking_id} for user {username} due to invalid time format: {e}")
                                self.listbox.insert(tk.END,
                                                    f"User: {username} | Movie: Invalid Show ID {show_id} | Seats: {', '.join(booking['seats'])} | Status: {booking['payment_status']} (Time Error)")
                        else:
                            self.listbox.insert(tk.END,
                                                f"User: {username} | Movie: Show Not Found (ID: {show_id}) | Seats: {', '.join(booking['seats'])} | Status: {booking['payment_status']}")
        except exceptions.FirebaseError as e:
            messagebox.showerror("Database Error", f"Could not load all bookings: {e}")


class TransactionHistoryScreen(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg=BG_COLOR)
        self.controller = controller
        tk.Label(self, text="Transaction History", font=FONT_MEDIUM, bg=BG_COLOR, fg=FG_COLOR).pack(pady=20)
        style = ttk.Style()
        style.configure("Treeview", background=LISTBOX_BG, foreground=FG_COLOR, fieldbackground=LISTBOX_BG,
                        rowheight=25, font=FONT_NORMAL)
        style.configure("Treeview.Heading", background=NEON_RED, foreground=FG_COLOR, font=FONT_BOLD)
        tree_frame = tk.Frame(self, bg=BG_COLOR);
        tree_frame.pack(pady=10, padx=20, fill="x", expand=True)
        self.tree = ttk.Treeview(tree_frame, columns=("ID", "Timestamp", "Username", "Movie", "Status", "Price"),
                                 show='headings')
        for col in ("ID", "Timestamp", "Username", "Movie", "Status", "Price"): self.tree.heading(col, text=col)
        self.tree.column('ID', width=150);
        self.tree.column('Timestamp', width=150);
        self.tree.column('Username', width=100)
        self.tree.pack(side="left", fill="both", expand=True)
        button_frame = tk.Frame(self, bg=BG_COLOR);
        button_frame.pack(pady=20)
        NeonButton(button_frame, text="Back", command=lambda: controller.show_frame("AdminMenu")).pack(side="left",
                                                                                                       padx=10,
                                                                                                       ipadx=10)
        self.bind("<<ShowFrame>>", self.on_show_frame)

    def on_show_frame(self, event=None):
        for i in self.tree.get_children(): self.tree.delete(i)
        try:
            transactions = db.reference('transactions').get() or {}
            sorted_trans = sorted(transactions.items(),
                                  key=lambda item: item[1].get('Timestamp', '') if item[1] else '', reverse=True)
            for trans_id, trans in sorted_trans:
                if not trans or not isinstance(trans, dict):
                    print(f"Skipping invalid transaction {trans_id}")
                    continue
                self.tree.insert("", "end", values=(
                    trans.get("transaction_id", "N/A")[:8] + "..",
                    trans.get("Timestamp", "N/A"),
                    trans.get("Username", "N/A"),
                    trans.get("Movie Title", "N/A"),
                    trans.get("Payment Status", "N/A"),
                    f"${trans.get('Price', 0.0):.2f}"
                ))
        except exceptions.FirebaseError as e:
            messagebox.showerror("Database Error", f"Could not load transaction history: {e}")


class NotificationsScreen(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg=BG_COLOR)
        self.controller = controller
        tk.Label(self, text="Notifications", font=FONT_MEDIUM, bg=BG_COLOR, fg=FG_COLOR).pack(pady=20)
        self.listbox = tk.Listbox(self, width=100, height=20, bg=LISTBOX_BG, fg=FG_COLOR, font=FONT_NORMAL)
        self.listbox.pack(pady=10, padx=20)
        button_frame = tk.Frame(self, bg=BG_COLOR);
        button_frame.pack(pady=20)
        NeonButton(button_frame, text="Clear Notifications", command=self.clear_notifications).pack(side="left",
                                                                                                    padx=10, ipadx=10)
        NeonButton(button_frame, text="Back", command=self.go_back).pack(side="left", padx=10, ipadx=10)
        self.bind("<<ShowFrame>>", self.on_show_frame)

    def on_show_frame(self, event=None):
        self.listbox.delete(0, tk.END)
        username = self.controller.current_session['username']
        try:
            notifications = db.reference(f'users/{username}/notifications').get() or {}
            sorted_notifications = sorted(notifications.items(),
                                          key=lambda item: item[1].get('timestamp', '') if item[1] else '',
                                          reverse=True)
            for notif_id, notif in sorted_notifications:
                if notif and isinstance(notif, dict):
                    self.listbox.insert(tk.END,
                                        f"{notif.get('timestamp', 'N/A')}: {notif.get('message', 'No message')}")
        except exceptions.FirebaseError as e:
            messagebox.showerror("Database Error", f"Could not load notifications: {e}")

    def clear_notifications(self):
        username = self.controller.current_session['username']
        try:
            db.reference(f'users/{username}/notifications').delete()
            messagebox.showinfo("Success", "Notifications cleared.")
            self.on_show_frame()
        except exceptions.FirebaseError as e:
            messagebox.showerror("Database Error", f"Could not clear notifications: {e}")

    def go_back(self):
        role = self.controller.current_session.get('role')
        frame = "AdminMenu" if role == 'admin' else "UserMenu"
        self.controller.show_frame(frame)


# --- Main Execution ---
if __name__ == "__main__":
    app = MovieTicketBookingSystem()
    initialize_firebase()
    cleanup_past_shows()
    app.after(5000, check_pay_later_deadlines)
    app.mainloop()