import time
import json
import requests
from flask import Flask, request, jsonify
from seleniumwire import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required!'}), 400

    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")

    driver = webdriver.Chrome(options=chrome_options)

    try:
        driver.get("https://www.jusbrasil.com.br/login")

        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.NAME, "email")))
        driver.find_element(By.NAME, "email").send_keys(email)
        driver.find_element(By.CSS_SELECTOR, 'button[type="submit"]').click()

        intercepted_request = driver.wait_for_request('/account-sign-up-or-in-by-email', timeout=10)

        first_payload = json.loads(intercepted_request.body.decode('utf-8'))
        event_data = first_payload.get('event_data', {})
        next_url = first_payload.get('nextUrl', '')

        headers = dict(intercepted_request.headers)
        new_headers = headers.copy()
        new_headers.pop('Content-Length', None)
        new_headers.pop('Host', None)
        new_headers.pop('Accept-Encoding', None)

        second_payload = {
            "event_data": event_data,
            "next_url": next_url,
            "password": password,
            "username": email
        }

        session = requests.Session()

        response = session.post(
            "https://www.jusbrasil.com.br/login",
            headers=new_headers,
            data=json.dumps(second_payload)
        )

        if response.status_code != 200:
            return jsonify({'error': 'Authentication failed!'}), 401

        

        for cookie in session.cookies:
            cookie_dict = {
                'name': cookie.name,
                'value': cookie.value,
                'domain': cookie.domain,
                'path': cookie.path,
                'secure': cookie.secure,
                'httpOnly': cookie.has_nonstandard_attr('HttpOnly')
            }
            driver.add_cookie(cookie_dict)

        # descomentar as linhas para visualizar a página após o login
        #driver.get("https://www.jusbrasil.com.br/acompanhamentos/processos")
        #time.sleep(30)

        return jsonify({
            'login_session_cookies': session.cookies.get_dict(),
            'page_cookies': driver.get_cookies(), 
        }, 200)

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        driver.quit()

if __name__ == '__main__':
    app.run(debug=True)
