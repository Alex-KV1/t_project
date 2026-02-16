import random


def generate_mock_products(len_products: int = 6) -> list:
    len_users_manger: int = 3
    product_names = [
        "Телевизор",
        "Магнитофон",
        "Планшет",
        "Память",
        "Колонка",
        "Клавиатуры",
    ]
    owners = [i for i in range(2, len_users_manger + 2)]

    products = []
    for i in range(1, len_products + 1):
        product = {
            "id": i,
            "name": random.choice(product_names),
            "price": random.randint(1000, 10000),
            "owner_id": random.choice(owners),
        }
        products.append(product)
    return products


def generate_mock_shops(num_shops: int = 5) -> list:
    len_users_manger: int = 3
    shop_names = ["Сарт", "Электрон", "МегаМаркет", "Лучшее", "Entered"]
    addresses = [
        "ул. Рокоссовского, 11",
        "ул. Нефтяги, 23",
        "ул. Шарова, 999",
        "ул. Фейковая, 666",
    ]
    owners = [i for i in range(2, len_users_manger + 2)]

    shops = []
    for i in range(1, num_shops + 1):
        shop = {
            "id": i,
            "name": random.choice(shop_names),
            "address": random.choice(addresses),
            "owner_id": random.choice(owners),
        }
        shops.append(shop)
    return shops


if __name__ == "__main__":

    product = generate_mock_products(20)
    shop = generate_mock_shops(15)

    print("MOCK_PRODUCTS:", product, end=f"\n{'*'*100}\n")
    print("MOCK_SHOPS:", shop, end=f"\n{'*'*100}\n")
