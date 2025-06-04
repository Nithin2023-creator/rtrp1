from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import json
import re
from datetime import datetime  # Import datetime module

app = Flask(__name__)
CORS(app)

# Load faculty data from JSON
with open('faculty_data.json', 'r') as file:
    faculty_data = json.load(file)

# General questions and answers
general_qa = {
    
    "How are you?": " I am fine. Hope you are doing well. I will feel blessed to assist you.",
    "hi": "Hi I am Tathya Bot! How can I assist you today?",
    "hello": "Hello I am Tathya Bot! How can I assist you today?",
    "KMIT": "Keshav Memorial Institute of Technology is an engineering college abbreviated as KMIT.",
    "what is your name?": "I am your TATHYA Chatbot! I can help you with faculty details or general information about the university.",
    "what can i ask you?": "You can ask me about our faculty members, their qualifications, experiences, seminars they've organized, and more. I also answer general queries related to the university.",
    "how do i contact the faculty?": "You can contact the faculty through their contact details provided on their profile page. Feel free to reach out directly for any inquiries!",
    "what is the university's mission?": "Our mission is to provide excellent education and foster innovation through research. We strive to develop well-rounded professionals who can lead in their fields.",
    "what are the operating hours?": "The faculty's operating hours are from 9:00 AM to 5:00 PM on weekdays. For emergencies or after-hours consultations, please refer to individual faculty pages for specific contact details.",
    "how do i register for a course?": "Course registration can be done through the university's online portal. Ensure that you check the course offerings and deadlines for timely registration.",
    "Tell me about KMIT?": "Keshav Memorial Institute of Technology is an engineering college abbreviated as KMIT. It offers B.Tech courses with specializations like Data Science, Machine Learning, Artificial Intelligence, Information Technology.",
    "what is the time?": "The current time is: ",  # Added new question for time
}

@app.route('/')
def home():
    return render_template('chatbot.html')

@app.route('/chat', methods=['POST'])
def chat():
    user_message = request.json['message'].strip().lower()

    # Respond to general questions
    if user_message in general_qa:
        if user_message == "what is the time?":
            # Get the current time and format it as HH:MM:SS
            current_time = datetime.now().strftime("%H:%M:%S")
            return jsonify({'reply': general_qa[user_message] + current_time})
        return jsonify({'reply': general_qa[user_message]})

    # Try to detect specific detail requests
    detail_keywords = ['qualification', 'experience', 'description', 'seminar', 'seminars']
    requested_detail = None
    for keyword in detail_keywords:
        if keyword in user_message:
            requested_detail = keyword
            break

    # Try to find a faculty mentioned in the message
    matched_faculty = None
    for faculty in faculty_data:
        faculty_name_lower = faculty['name'].lower()
        if any(part in user_message for part in faculty_name_lower.split()):
            matched_faculty = faculty
            break

    # If a faculty match is found
    if matched_faculty:
        name = matched_faculty['name']

        if requested_detail:
            if requested_detail == 'qualification':
                reply = f"**{name}** holds the qualification: {matched_faculty['qualification']}.\n\nLet me know your queries.😊"
            elif requested_detail == 'experience':
                reply = f"**{name}** has {matched_faculty['experience']} of experience.\n\nExperience always matters more. 😎"
            elif requested_detail == 'description':
                reply = f"Here’s a brief about **{name}**:\n{matched_faculty['description']}\n\n Don't hesitate to reach out to me on further queries.😇 "
            elif 'seminar' in requested_detail:
                seminar_lines = [
                    f"- **{s['topic']}** (Date: {s['date']}, Status: {s['status']})"
                    for s in matched_faculty['seminars']
                ]
                reply = f"**{name}** has organized the following seminars:\n" + '\n'.join(seminar_lines)
            else:
                reply = "Please specify whether you're asking about qualification, experience, description, or seminars."
        else:
            # Provide full details
            reply = f"Here’s more about **{name}**:\n\n"
            reply += f"**Qualification**:\n  - {matched_faculty['qualification']}\n\n"
            reply += f"**Experience**:\n  - {matched_faculty['experience']}\n\n"
            reply += f"**Description**:\n  - {matched_faculty['description']}\n\n"
            reply += f"**Seminars Organized**:\n"
            for seminar in matched_faculty['seminars']:
                reply += f"  - **{seminar['topic']}** (Date: {seminar['date']}, Status: {seminar['status']})\n"
            reply += "\nLet me know if you'd like more details about any of these topics."

        return jsonify({'reply': reply})

    # Default fallback
    return jsonify({'reply': "I’m sorry, I didn’t understand your question. Please try asking about a faculty member or general information."})

if __name__ == '__main__':
    app.run(debug=True)
