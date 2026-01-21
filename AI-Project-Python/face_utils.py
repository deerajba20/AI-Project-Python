import face_recognition
import numpy as np


def get_face_descriptor(image_np):
    """
    Finds faces in an image using an adaptive approach for speed and accuracy.
    - First, it tries a fast scan. If that fails, it uses a more intensive scan.
    - Returns descriptor if exactly one face is found.
    - Returns None if no faces are found.
    - Returns 'multiple' if more than one face is found.
    """
    # 1. Try a fast, standard scan first
    face_locations = face_recognition.face_locations(image_np)

    # 2. If no faces are found, try a more intensive upsampled scan
    if len(face_locations) == 0:
        face_locations = face_recognition.face_locations(image_np, number_of_times_to_upsample=2)

    # 3. Process the results
    if len(face_locations) == 0:
        return None

    if len(face_locations) > 1:
        return 'multiple'

    # If we get here, there is exactly one face
    face_encodings = face_recognition.face_encodings(image_np, face_locations)
    return face_encodings[0]


def find_matches_in_image(image_np, known_descriptors, known_names, tolerance=0.55):
    """
    Finds all faces in an image and checks them against all known descriptors.
    Uses an adaptive scan for better performance.
    """
    # 1. Try a fast, standard scan first
    unknown_face_locations = face_recognition.face_locations(image_np)

    # 2. If no faces are found, try a more intensive upsampled scan
    if len(unknown_face_locations) == 0:
        unknown_face_locations = face_recognition.face_locations(image_np, number_of_times_to_upsample=2)

    unknown_face_encodings = face_recognition.face_encodings(image_np, unknown_face_locations)

    match_results = []
    unique_matched_names = set()

    for (top, right, bottom, left), face_encoding in zip(unknown_face_locations, unknown_face_encodings):
        matches = face_recognition.compare_faces(known_descriptors, face_encoding, tolerance)
        name = "Unknown"

        if True in matches:
            matched_indices = [i for (i, match) in enumerate(matches) if match]
            names_for_this_face = []
            for index in matched_indices:
                matched_name = known_names[index]
                names_for_this_face.append(matched_name)
                unique_matched_names.add(matched_name)
            name = ", ".join(names_for_this_face)

        match_results.append({
            'name': name,
            'location': {'top': top, 'right': right, 'bottom': bottom, 'left': left}
        })

    matches_found = len(unique_matched_names)

    return {
        'matches_found': matches_found,
        'match_results': match_results
    }

