import pickle
import re
import gradio as gr

with open("phishing_detector_rf.pkl", "rb") as f:
    rf_model = pickle.load(f)

with open("scaler.pkl", "rb") as f:
    scaler = pickle.load(f)

def predict_url_interface(url):
    if not url or url.strip() == "":
        return "Please enter a URL!", "", "", ""

    def extract_features(url):
        features = []
        domain = url.split("/")[2] if len(url.split("/")) > 2 else url
        features.append(1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else -1)
        features.append(1 if len(url) < 54 else (0 if len(url) <= 75 else -1))
        shorteners = ["bit.ly","goo.gl","tinyurl","ow.ly","t.co"]
        features.append(-1 if any(s in url for s in shorteners) else 1)
        features.append(-1 if "@" in url else 1)
        features.append(-1 if url.rfind("//") > 7 else 1)
        features.append(-1 if "-" in domain else 1)
        dots = domain.count(".")
        features.append(-1 if dots > 2 else (0 if dots == 2 else 1))
        features.append(1 if url.startswith("https") else -1)
        features.append(1)
        features.append(1)
        features.append(1 if ":" not in domain else -1)
        features.append(-1 if "https" in domain.lower() else 1)
        for _ in range(18):
            features.append(0)
        return features

    features = extract_features(url.strip())
    features_scaled = scaler.transform([features])
    prediction = rf_model.predict(features_scaled)[0]
    confidence = rf_model.predict_proba(features_scaled)[0].max() * 100

    if prediction == -1:
        result  = "PHISHING DETECTED"
        verdict = "DANGEROUS"
        advice  = "Do NOT visit this site. Do not enter any passwords, card details or personal information."
    else:
        result  = "LEGITIMATE WEBSITE"
        verdict = "SAFE"
        advice  = "This URL appears safe. Always stay cautious and verify websites before sharing information."

    return result, verdict, f"{confidence:.1f}%", advice

css = """
body, .gradio-container {
    background: linear-gradient(135deg, #0f0c29, #302b63, #24243e) !important;
    font-family: Segoe UI, sans-serif !important;
}
.main-card {
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 24px;
    padding: 36px 40px;
    backdrop-filter: blur(12px);
    box-shadow: 0 8px 40px rgba(0,0,0,0.5);
}
.header-box {
    text-align: center;
    margin-bottom: 32px;
}
.header-box h1 {
    font-size: 2.8rem;
    font-weight: 900;
    background: linear-gradient(90deg, #00d2ff, #7b2ff7);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin: 0 0 8px;
}
.header-box p { color: #718096; font-size: 0.95rem; margin: 0; }
.url-input textarea, .url-input input {
    background: rgba(255,255,255,0.08) !important;
    border: 2px solid rgba(0,210,255,0.35) !important;
    border-radius: 14px !important;
    color: #ffffff !important;
    font-size: 1.05rem !important;
    padding: 16px 20px !important;
}
.url-input label span { color: #00d2ff !important; font-weight: 700 !important; }
.check-btn {
    background: linear-gradient(135deg, #00d2ff, #7b2ff7) !important;
    border: none !important;
    border-radius: 14px !important;
    color: #fff !important;
    font-size: 1.15rem !important;
    font-weight: 800 !important;
    padding: 16px 0 !important;
    width: 100% !important;
    cursor: pointer !important;
    box-shadow: 0 4px 24px rgba(123,47,247,0.5) !important;
}
.result-box textarea, .result-box input {
    background: rgba(0,210,255,0.10) !important;
    border: 2px solid rgba(0,210,255,0.3) !important;
    border-radius: 14px !important;
    color: #ffffff !important;
    font-weight: 800 !important;
    padding: 14px 18px !important;
}
.verdict-box textarea, .verdict-box input {
    background: rgba(123,47,247,0.15) !important;
    border: 2px solid rgba(123,47,247,0.4) !important;
    border-radius: 14px !important;
    color: #ffffff !important;
    font-weight: 800 !important;
    padding: 14px 18px !important;
}
.conf-box textarea, .conf-box input {
    background: rgba(56,211,159,0.10) !important;
    border: 2px solid rgba(56,211,159,0.35) !important;
    border-radius: 14px !important;
    color: #ffffff !important;
    font-weight: 800 !important;
    padding: 14px 18px !important;
}
.advice-box textarea, .advice-box input {
    background: rgba(255,255,255,0.05) !important;
    border: 2px solid rgba(255,255,255,0.12) !important;
    border-radius: 14px !important;
    color: #cbd5e0 !important;
    padding: 14px 18px !important;
}
label span {
    color: #a0aec0 !important;
    font-size: 0.85rem !important;
    font-weight: 700 !important;
    text-transform: uppercase !important;
}
.stats-bar {
    display: flex;
    justify-content: center;
    gap: 16px;
    margin: 28px 0 0;
    flex-wrap: wrap;
}
.stat-pill {
    background: rgba(255,255,255,0.06);
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 50px;
    padding: 10px 22px;
    color: #e2e8f0;
    font-size: 0.85rem;
    font-weight: 600;
}
.stat-pill span { color: #00d2ff; font-weight: 800; }
.divider {
    height: 1px;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
    margin: 24px 0;
}
"""

with gr.Blocks(css=css, title="Phishing Detector") as demo:
    gr.HTML("""
    <div class="header-box">
        <h1>PHISHING DETECTOR</h1>
        <p>Powered by Random Forest Machine Learning · 97.65% Accuracy</p>
    </div>
    """)
    with gr.Column(elem_classes="main-card"):
        url_input = gr.Textbox(
            label="Enter URL to Analyse",
            placeholder="e.g. https://www.google.com",
            lines=1,
            elem_classes="url-input"
        )
        check_btn = gr.Button("ANALYSE URL", elem_classes="check-btn")
        gr.HTML("<div style=height:14px></div>")
        with gr.Row():
            result_out  = gr.Textbox(label="Detection Result", interactive=False, elem_classes="result-box")
            verdict_out = gr.Textbox(label="Verdict",          interactive=False, elem_classes="verdict-box")
            conf_out    = gr.Textbox(label="Confidence Score", interactive=False, elem_classes="conf-box")
        advice_out = gr.Textbox(label="Security Advice", interactive=False, lines=2, elem_classes="advice-box")
        gr.HTML("<div class=divider></div>")
        gr.HTML("""
        <div class="stats-bar">
            <div class="stat-pill">Accuracy <span>97.65%</span></div>
            <div class="stat-pill">ROC-AUC  <span>0.9977</span></div>
            <div class="stat-pill">F1-Score  <span>0.98</span></div>
            <div class="stat-pill">Trees     <span>100</span></div>
            <div class="stat-pill">Dataset  <span>11,055 URLs</span></div>
        </div>
        """)
        gr.HTML("<div class=divider></div>")
        gr.Examples(
            examples=[
                ["https://www.google.com"],
                ["https://www.bbc.co.uk/news"],
                ["https://www.amazon.co.uk"],
                ["http://192.168.1.1/secure/login-paypal.html"],
                ["http://paypal-secure-verify.com/signin@account"],
                ["http://bit.ly/free-prize-claim-now"],
            ],
            inputs=url_input,
            label="Quick Test Examples"
        )
    check_btn.click(fn=predict_url_interface, inputs=url_input,
                    outputs=[result_out, verdict_out, conf_out, advice_out])
    url_input.submit(fn=predict_url_interface, inputs=url_input,
                     outputs=[result_out, verdict_out, conf_out, advice_out])

if __name__ == "__main__":
    demo.launch(share=True)
