import cv2
import mediapipe as mp
import webbrowser
import time
import pyautogui  # For scrolling functionality

# Initialize MediaPipe Hands module
mp_hands = mp.solutions.hands
hands = mp_hands.Hands()
mp_draw = mp.solutions.drawing_utils

cap = cv2.VideoCapture(0)

# Variables to track finger count and time
last_count = 0
last_time = 0
scrolling = False

# Function to count fingers
def count_fingers(hand_landmarks):
    fingers = []
    tip_ids = [4, 8, 12, 16,20]
    
    # Thumb
    if hand_landmarks.landmark[tip_ids[0]].x < hand_landmarks.landmark[tip_ids[0] - 1].x:
        fingers.append(1)
    else:
        fingers.append(0)
    
    # Other 4 fingers
    for id in range(1, 5):
        if hand_landmarks.landmark[tip_ids[id]].y < hand_landmarks.landmark[tip_ids[id] - 2].y:
            fingers.append(1)
        else:
            fingers.append(0)
    
    return fingers.count(1)

# Start video capture
while True:
    success, img = cap.read()
    if not success:
        continue  # Skip if there's an error reading the frame

    # Convert the image to RGB for processing
    img_rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
    results = hands.process(img_rgb)

    # Check if landmarks are detected
    if results.multi_hand_landmarks:
        for handLms in results.multi_hand_landmarks:
            # Draw the hand landmarks
            mp_draw.draw_landmarks(img, handLms, mp_hands.HAND_CONNECTIONS)

            # Count the number of fingers
            finger_count = count_fingers(handLms)

            # Get the current time to manage gesture timing
            current_time = time.time()

            # Implement scrolling based on finger count
            if finger_count != last_count and current_time - last_time > 1:
                last_count = finger_count
                last_time = current_time

                # Scroll up with 1 finger (Thumb)
                if finger_count == 1:
                    pyautogui.scroll(500)  # Scroll up
                    scrolling = True

                # Scroll down with 5 fingers
                elif finger_count == 5:
                    pyautogui.scroll(-500)  # Scroll down
                    scrolling = True

                # Stop scrolling with fist (0 fingers)
                elif finger_count == 0:
                    scrolling = False

                # Open the corresponding URL based on finger count
                if finger_count == 1:
                    webbrowser.open("http://localhost:4009/admin_dashboard")
                elif finger_count == 2:
                    webbrowser.open("http://localhost:4009/manage_users")
                elif finger_count == 3:
                    webbrowser.open("http://localhost:4009/reports")
                elif finger_count == 4:
                    webbrowser.open("http://localhost:4009/notifications")
                
    # Display the video feed with hand landmarks
    cv2.imshow("Hand Gesture", img)

    # Exit if 'q' is pressed
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

# Release the video capture and close the windows
cap.release()
cv2.destroyAllWindows()
