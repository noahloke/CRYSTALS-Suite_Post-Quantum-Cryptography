from flask import Flask, request, render_template, jsonify
import subprocess
import re

def sanitize(input):
    return re.sub(r'[^\w\s]', '', input)

web_app = Flask(__name__)

@web_app.route('/projects/explore-crystals')
def home():
    return render_template("home.html")
    
@web_app.route('/projects/explore-crystals/kyber')
def kyber():
    return render_template("kyber.html")
    
@web_app.route('/projects/explore-crystals/dilithium')
def dilithium():
    return render_template("dilithium.html")

@web_app.route('/projects/explore-crystals/comparison', methods=['GET', 'POST'])
def comparison():
    aes256Key = ""
    aesEncryptOutput = ""
    aesDecryptOutput = ""
    rsaKeys = ""
    rsaEncryptOutput = ""
    rsaDecryptOutput = ""
    dilithiumTestOutput = ""
    kyberTestOutput = ""
    comparisonTestOutput = ""
    
    if request.method == 'POST':
        action = request.form.get('action', '')

        if action == 'generateAESKey':
            process = subprocess.run(['executables/generate_aes_256'], capture_output=True, text=True)
            aes256Key = process.stdout.strip()

        elif action == 'aesEncrypt':
            message = sanitize(request.form.get('message', ''))
            aes256Key2 = sanitize(request.form.get('aes256Key2', ''))
            process = subprocess.run(['executables/aes_encrypt', message, aes256Key2], capture_output=True, text=True)
            aesEncryptOutput = process.stdout.strip()

        elif action == 'aesDecrypt':
            ciphertext = sanitize(request.form.get('ciphertext', ''))
            aes256Key3 = sanitize(request.form.get('aes256Key3', ''))
            process = subprocess.run(['executables/aes_decrypt', ciphertext, aes256Key3], capture_output=True, text=True)
            aesDecryptOutput = process.stdout.strip()

        if action == 'generateRSAKeys':
            process = subprocess.run(['executables/generate_rsa_keys'], capture_output=True, text=True)
            rsaKeys = process.stdout.strip()

        elif action == 'rsaEncrypt':
            aes256KeyForRSA = sanitize(request.form.get('aes256KeyForRSA', ''))
            rsaPublicKey = sanitize(request.form.get('rsaPublicKey', ''))
            process = subprocess.run(['executables/rsa_encrypt', aes256KeyForRSA, rsaPublicKey], capture_output=True, text=True)
            rsaEncryptOutput = process.stdout.strip()

        elif action == 'rsaDecrypt':
            rsaEncryptedAESKey = sanitize(request.form.get('rsaEncryptedAESKey', ''))
            rsaPrivateKey = sanitize(request.form.get('rsaPrivateKey', ''))
            process = subprocess.run(['executables/rsa_decrypt', rsaEncryptedAESKey, rsaPrivateKey], capture_output=True, text=True)
            rsaDecryptOutput = process.stdout.strip()

        elif action == 'dilithiumTest':
            process = subprocess.run(['executables/noah_test_dilithium5aes'], capture_output=True, text=True)
            dilithiumTestOutput = process.stdout.strip()

        elif action == 'kyberTest':
            userInput = sanitize(request.form.get('userInput', ''))
            process = subprocess.run(['executables/kyber_test1024', userInput], capture_output=True, text=True)
            kyberTestOutput = process.stdout.strip()
        
        elif action == 'comparisonTest':
            iterations = sanitize(request.form.get('iterations', ''))
            process = subprocess.run(['executables/comparison_test1024', iterations], capture_output=True, text=True)
            comparisonTestOutput = process.stdout.strip()
        
        return jsonify({
            "aes256Key": aes256Key,
            "aesEncryptOutput": aesEncryptOutput,
            "aesDecryptOutput": aesDecryptOutput,
            "rsaKeys": rsaKeys,
            "rsaEncryptOutput": rsaEncryptOutput,
            "rsaDecryptOutput": rsaDecryptOutput,
            "dilithiumTestOutput": dilithiumTestOutput,
            "kyberTestOutput": kyberTestOutput,
            "comparisonTestOutput": comparisonTestOutput
        })

    return render_template(
        "comparison.html",
        aes256Key=aes256Key,
        aesEncryptOutput=aesEncryptOutput,
        aesDecryptOutput=aesDecryptOutput,
        rsaKeys=rsaKeys,
        rsaEncryptOutput=rsaEncryptOutput,
        rsaDecryptOutput=rsaDecryptOutput,
        dilithiumTestOutput=dilithiumTestOutput,
        kyberTestOutput=kyberTestOutput,
        comparisonTestOutput=comparisonTestOutput
    )

#if __name__ == '__main__':
#    web_app.run(host='0.0.0.0', port=5000, debug=True)
