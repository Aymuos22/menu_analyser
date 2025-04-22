import os
import base64
import uuid
import requests
import pandas as pd
from flask import Flask, render_template, request, send_file, redirect, url_for, session, jsonify
from werkzeug.utils import secure_filename
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from groq import Groq

# Load env variables
load_dotenv()

# --- Flask setup ---
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default-secret")
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['IMAGE_FOLDER'] = 'static/food_images'
app.config['EXCEL_PATH'] = 'static/menu_output.xlsx'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['IMAGE_FOLDER'], exist_ok=True)

# --- Extensions ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# --- Utils ---
def encode_image(image_path):
    with open(image_path, "rb") as f:
        return base64.b64encode(f.read()).decode('utf-8')

def extract_items_from_image(image_path):
    encoded = encode_image(image_path)
    prompt = "Extract only food item names and prices from this restaurant menu image. Format: Item Name - Price. Only give food items, no description, no headings."

    response = client.chat.completions.create(
        model="meta-llama/llama-4-scout-17b-16e-instruct",
        messages=[
            {"role": "user", "content": [
                {"type": "text", "text": prompt},
                {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{encoded}"}}
            ]}
        ]
    )

    result = response.choices[0].message.content.strip()
    items = []

    for line in result.splitlines():
        if "-" in line:
            parts = line.split("-", 1)
            item, price = parts[0].strip(), parts[1].strip()
            if item and price:
                items.append((item, price))
    return items

def get_translation_and_info_multilang(item_name, languages):
    results = {}
    
    # Ensure English is included
    if "English" not in languages:
        languages.append("English")

    for lang in languages:
        prompt = (
            f"Translate the food item '{item_name}' to {lang}. "
            f"Then provide:\n"
            f"1. A short 1-line description in {lang}\n"
            f"2. A list of ingredients in {lang}\n"
            f"3. Estimated calories in kcal.\n"
            f"Format strictly as:\n"
            f"Translation: <translated_name>\n"
            f"Description: <short description>\n"
            f"Ingredients: <comma-separated list>\n"
            f"Calories: <number>"
        )

        try:
            response = client.chat.completions.create(
                model="meta-llama/llama-4-scout-17b-16e-instruct",
                messages=[{"role": "user", "content": prompt}]
            )
            lines = response.choices[0].message.content.strip().split("\n")
            data = {"translated": "", "description": "", "ingredients": "", "calories": ""}
            for line in lines:
                if ":" in line:
                    key, val = line.split(":", 1)
                    key = key.strip().lower()
                    val = val.strip()
                    if "translation" in key:
                        data["translated"] = val
                    elif "description" in key:
                        data["description"] = val
                    elif "ingredients" in key:
                        data["ingredients"] = val
                    elif "calories" in key:
                        data["calories"] = val
            results[lang] = data
        except Exception as e:
            print(f"[ERROR] Translation failed for {item_name} in {lang}:", e)
            results[lang] = {"translated": "", "description": "", "ingredients": "", "calories": ""}
    
    return results


def get_food_image_url(query):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        url = f"https://www.google.com/search?tbm=isch&q={query.replace(' ', '+')}+dish"
        soup = BeautifulSoup(requests.get(url, headers=headers).text, "html.parser")
        images = soup.find_all("img")
        for img in images[2:10]:
            link = img.get("src")
            if link and link.startswith("http"):
                return link
    except Exception as e:
        print("[ERROR] Image fetch failed:", e)
    return None

def download_image(url, path):
    try:
        r = requests.get(url, stream=True, timeout=10)
        if r.status_code == 200:
            with open(path, "wb") as f:
                for chunk in r.iter_content(1024):
                    f.write(chunk)
            return True
    except Exception as e:
        print("[ERROR] Download failed:", e)
    return False

@app.before_request
def clean_image_folder():
    if request.endpoint in ['index', 'change_image'] and 'user_id' in session:
        user_folder = os.path.join(app.config['IMAGE_FOLDER'], f"user_{session['user_id']}")
        if os.path.exists(user_folder):
            for f in os.listdir(user_folder):
                try: os.remove(os.path.join(user_folder, f))
                except: pass

# --- Auth routes ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = User(username=request.form['username'], password=bcrypt.generate_password_hash(request.form['password']).decode('utf-8'))
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template("register.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        return "Invalid credentials"
    return render_template("login.html")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- Main ---
@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    items_with_images = []
    user_id = session['user_id']
    user_dir = os.path.join(app.config['IMAGE_FOLDER'], f"user_{user_id}")
    os.makedirs(user_dir, exist_ok=True)

    if request.method == 'POST':
        selected_languages = request.form.getlist("languages")
        uploaded_files = request.files.getlist('menu_images')
        all_items = []

        for file in uploaded_files:
            filename = secure_filename(file.filename)
            path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(path)
            all_items.extend(extract_items_from_image(path))

        full_data = []
        for name, price in all_items:
            info = get_translation_and_info_multilang(name, selected_languages)
            unique_name = f"{name.replace(' ', '_')}_{uuid.uuid4().hex[:8]}.jpg"
            image_path = os.path.join(user_dir, unique_name)
            img_url = get_food_image_url(name)
            if img_url:
                download_image(img_url, image_path)

            row = {"Item": name, "Price": price, "Image": image_path.replace("static", "/static")}
            for lang in selected_languages:
                row[f"Translated Name ({lang})"] = info[lang]["translated"]
                row[f"Description ({lang})"] = info[lang]["description"]
                row[f"Ingredients ({lang})"] = info[lang]["ingredients"]
                row[f"Calories ({lang})"] = info[lang]["calories"]
            full_data.append(row)

        pd.DataFrame(full_data).to_excel(app.config['EXCEL_PATH'], index=False)
        items_with_images = [(r["Item"], r["Price"], r["Image"]) for r in full_data]

    return render_template("index.html", items=items_with_images)

@app.route('/download')
def download_excel():
    return send_file(app.config['EXCEL_PATH'], as_attachment=True)

@app.route('/change-image')
def change_image():
    name = request.args.get("name")
    if not name or 'user_id' not in session:
        return jsonify({"error": "No name provided"}), 400

    img_url = get_food_image_url(name)
    if not img_url:
        return jsonify({"error": "No image found"}), 404

    filename = f"{name.replace(' ', '_')}_{uuid.uuid4().hex[:8]}.jpg"
    user_dir = os.path.join(app.config['IMAGE_FOLDER'], f"user_{session['user_id']}")
    path = os.path.join(user_dir, filename)

    if download_image(img_url, path):
        return jsonify({"new_url": path.replace("static", "/static")})
    return jsonify({"error": "Image download failed"}), 500

# --- Main ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
