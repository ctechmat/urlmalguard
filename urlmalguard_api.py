from flask import Flask, render_template, request, jsonify, session
from urlmalguard_script import url_analysis
import secrets
import translations

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)

# Route pour la page d'accueil avec le formulaire
@app.route('/', methods=['GET', 'POST'])
def index():
    # Si un formulaire a été soumis pour changer la langue
    if request.method == 'POST':
        session['lang'] = request.form.get('lang', 'fr')  # Langue par défaut : français

    # Langue choisie ou par défaut 'fr'
    lang = session.get('lang', 'fr')

    # Passer les traductions au template
    return render_template('index.html', translations=translations.translations[lang])

# Route pour analyser l'URL depuis le formulaire et afficher les résultats dans un template HTML
@app.route('/analyse', methods=['POST'])
def analyse():
    url = request.form['url']
    resultats = url_analysis(url)
    # Langue choisie ou par défaut 'fr'
    lang = session.get('lang', 'fr')
    
    # Passer les traductions et les résultats d'analyse au template
    return render_template('resultats.html', url=url, resultats=resultats, translations=translations.translations[lang])

# Route pour l'API qui retourne les résultats en JSON
@app.route('/api/analyse', methods=['GET'])
def api_analyse():
    url = request.args.get('url')
    if not url:
        return jsonify({"error": "URL is required without ip and custom port"}), 400
    
    resultats = url_analysis(url)
    return jsonify(resultats)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
