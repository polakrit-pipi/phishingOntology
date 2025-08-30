Phish Ontology Prototype
------------------------
ติดตั้ง dependency:
    pip install -r requirements.txt

รันตัวอย่าง:
    uvicorn webapp:app --reload

ไฟล์สำคัญ:
- phish_detector/detector.py : โมดูลหลัก (feature extraction + reasoning)
- phish_detector/utils.py : ฟังก์ชันช่วย (parsing, heuristics)
- example_run.py : ตัวอย่างใช้งาน (demo)
