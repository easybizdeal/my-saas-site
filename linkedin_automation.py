from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import time

def send_linkedin_message(profile_url, message, li_at_cookie, jsessionid):
    options = Options()
    options.add_argument("--headless")  # Remove if you want visible browser
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1920,1080")

    driver = webdriver.Chrome(options=options)

    try:
        # Open LinkedIn and set cookies
        driver.get("https://www.linkedin.com")
        driver.delete_all_cookies()
        driver.add_cookie({'name': 'li_at', 'value': li_at_cookie, 'domain': '.linkedin.com'})
        driver.add_cookie({'name': 'JSESSIONID', 'value': jsessionid, 'domain': '.linkedin.com'})

        # Navigate to profile
        driver.get(profile_url)
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, 'body')))
        time.sleep(3)

        # Locate and click the "Message" button
        try:
            msg_btn = WebDriverWait(driver, 15).until(
                EC.presence_of_element_located((By.XPATH, '//span[text()="Message"]/ancestor::button'))
            )
            driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", msg_btn)
            time.sleep(1)
            driver.execute_script("arguments[0].click();", msg_btn)
            time.sleep(3)
        except TimeoutException:
            raise Exception("❌ 'Message' button not found or not clickable. Make sure the user is a connection.")

        # Locate the message input box
        input_box = WebDriverWait(driver, 15).until(
            EC.visibility_of_element_located((By.XPATH, '//div[@role="textbox" and contains(@aria-label, "Write a message")]'))
        )
        driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", input_box)
        driver.execute_script("arguments[0].click();", input_box)
        input_box.send_keys(message)
        time.sleep(2)

        # Send message
        send_btn = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.XPATH, '//button[contains(@class, "msg-form__send-button")]'))
        )
        send_btn.click()
        print(f"✅ Message sent successfully to: {profile_url}")

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        raise

    finally:
        driver.quit()
