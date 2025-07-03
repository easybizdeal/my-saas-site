import os
import json
from flask import Flask, render_template, request, redirect, url_for, flash
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

app = Flask(__name__)
app.secret_key = 'super_secret_key'

# Ensure cookies directory exists
os.makedirs('cookies', exist_ok=True)

@app.route('/linkedin-connect', methods=['GET'])
def linkedin_connect():
    return render_template('linkedin_connect.html')

@app.route('/linkedin-connect/start', methods=['POST'])
def start_linkedin_login():
    user_id = str(request.form.get('user_id'))
    cookie_path = f'cookies/{user_id}/linkedin_cookies.json'

    # Launch browser for manual login
    options = Options()
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_experimental_option("detach", True)  # Keep browser open
    driver = webdriver.Chrome(options=options)

    try:
        driver.get('https://www.linkedin.com/login')
        flash('👉 A browser window has been opened. Please log in manually and close the browser when done.', 'info')
        input("⏳ Press ENTER here after you finish logging in on the opened browser window...")

        # Save cookies
        cookies = driver.get_cookies()
        os.makedirs(f'cookies/{user_id}', exist_ok=True)
        with open(cookie_path, 'w') as f:
            json.dump(cookies, f)

        flash('✅ LinkedIn login session saved successfully!', 'success')
    except Exception as e:
        flash(f"❌ Error: {str(e)}", 'danger')
    finally:
        driver.quit()

    return redirect(url_for('linkedin_connect'))

if __name__ == '__main__':
    app.run(debug=True)