import time
# store all registered cards here
cards = {}
def add_card():
    card_id = input("\nEnter Card ID: ").strip()
    owner = input("Enter Owner Name: ").strip()
    if card_id in cards:
        print("This card is already registered!")
        return
    # save card with default protection off
    cards[card_id] = {
        "owner": owner,
        "blocked": False,
        "scan_attempts": 0
    }
    print(f"Card '{card_id}' registered successfully for {owner}.")
def scan_card():
    card_id = input("\nEnter Card ID to Scan: ").strip()
    if card_id not in cards:
        print("Card not found in system.")
        return
    card = cards[card_id]
    # check if card is blocked before allowing scan
    if card["blocked"]:
        card["scan_attempts"] += 1
        print(f"ACCESS DENIED! Card '{card_id}' is RFID blocked.")
        print(f"Total unauthorized attempts: {card['scan_attempts']}")
    else:
        print(f"Scan successful! Card belongs to: {card['owner']}")
def block_card():
    card_id = input("\nEnter Card ID to Block: ").strip()
    if card_id not in cards:
        print("Card not found.")
        return
    # enable rfid blocking on this card
    cards[card_id]["blocked"] = True
    print(f"Card '{card_id}' is now RFID protected.")
def unblock_card():
    card_id = input("\nEnter Card ID to Unblock: ").strip()
    if card_id not in cards:
        print("Card not found.")
        return
    cards[card_id]["blocked"] = False
    print(f"Card '{card_id}' has been unblocked.")
def show_all():
    if not cards:
        print("\nNo cards registered yet.")
        return
    print("\n--- All Registered Cards ---")
    for cid, info in cards.items():
        status = "BLOCKED" if info["blocked"] else "Active"
        print(f"ID: {cid} | Owner: {info['owner']} | Status: {status} | Attempts: {info['scan_attempts']}")
def main():
    print("=== RFID Blocking Simulator ===")
    print("Rhombix Technologies - Cyber Security Task 2")
    while True:
        print("\n1. Register Card")
        print("2. Scan Card")
        print("3. Block Card")
        print("4. Unblock Card")
        print("5. View All Cards")
        print("6. Exit")
        choice = input("\nChoose an option (1-6): ").strip()
        if choice == "1":
            add_card()
        elif choice == "2":
            scan_card()
        elif choice == "3":
            block_card()
        elif choice == "4":
            unblock_card()
        elif choice == "5":
            show_all()
        elif choice == "6":
            print("Exiting program. Goodbye!")
            break
        else:
            print("Invalid option! Please choose between 1-6.")
if __name__ == "__main__":
    main()