# linkedin_cookie_collector.py
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time

def collect_linkedin_cookies():
    options = Options()
    options.add_experimental_option("detach", False)  # browser will close
    driver = webdriver.Chrome(options=options)

    try:
        driver.get("https://www.linkedin.com/login")
        print("👉 Waiting for user to complete LinkedIn login...")

        # Wait until redirected to LinkedIn feed/home after login
        while "feed" not in driver.current_url:
            time.sleep(2)

        cookies = driver.get_cookies()
        li_at = next((c['value'] for c in cookies if c['name'] == 'li_at'), None)
        jsessionid = next((c['value'] for c in cookies if c['name'] == 'JSESSIONID'), None)

        return li_at, jsessionid

    except Exception as e:
        print("❌ Error collecting cookies:", e)
        return None, None

    finally:
        driver.quit()
