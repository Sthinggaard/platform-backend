from enum import StrEnum


class PrimaryBusinessActivity(StrEnum):
    DIGITAL_PRODUCTS = "digital_products"
    CLIENT_EXPERTISE = "client_expertise"
    PHYSICAL_PRODUCTS = "physical_products"
    SELL_OR_DISTRIBUTE = "sell_or_distribute"
    MOVE_GOODS_OR_PEOPLE = "move_goods_or_people"


class CriticalBusinessActivity(StrEnum):
    CREATE = "create"
    SERVE_CUSTOMERS = "serve_customers"
    FULFIL_ORDERS = "fulfil_orders"
    PLAN_AND_MAKE = "plan_and_make"
    DELIVER_GOODS = "deliver_goods"


class CustomerVisibleImpact(StrEnum):
    """What customers would notice first if operations stopped. Multi-select —
    more than one of these is commonly true at once."""

    LATE_OR_MISSED_DELIVERIES = "late_or_missed_deliveries"
    CANNOT_PLACE_OR_PAY_FOR_ORDERS = "cannot_place_or_pay_for_orders"
    CANNOT_REACH_SUPPORT = "cannot_reach_support"
    PRODUCT_OR_SERVICE_STOPS_WORKING = "product_or_service_stops_working"
    WRONG_OR_DELAYED_INFORMATION = "wrong_or_delayed_information"


class TimeSensitivity(StrEnum):
    MINUTES = "minutes"
    HOURS = "hours"
    SAME_DAY = "same_day"
    FEW_DAYS = "few_days"
    RARELY_URGENT = "rarely_urgent"


class HardToReplaceQuickly(StrEnum):
    """What would be genuinely hard to replace on short notice. Multi-select —
    a business can have more than one true single point of failure."""

    KEY_PEOPLE_OR_EXPERTISE = "key_people_or_expertise"
    A_SUPPLIER_OR_PARTNER = "a_supplier_or_partner"
    PHYSICAL_STOCK_OR_EQUIPMENT = "physical_stock_or_equipment"
    A_LICENCE_OR_APPROVAL = "a_licence_or_approval"
    CUSTOMER_TRUST = "customer_trust"


class OperationalReach(StrEnum):
    ONLINE = "online"
    SINGLE_LOCATION = "single_location"
    MULTIPLE_LOCATIONS = "multiple_locations"
    MANY_SITES_OR_PARTNERS = "many_sites_or_partners"
