class BillingModule:
    def __init__(self):
        self.free_tier_limit = 5  # 5 GB
        self.premium_cost = 10  # $10/month
        self.pay_as_you_go_rate = 0.10  # $0.10/GB

    def calculate_cost(self, usage_gb, plan="free"):
        """
        Calculate the cost based on usage and plan.
        :param usage_gb: Data usage in GB.
        :param plan: Billing plan (free, premium, pay-as-you-go).
        :return: Cost in dollars.
        """
        if plan == "free":
            if usage_gb > self.free_tier_limit:
                raise ValueError("Free tier limit exceeded.")
            return 0
        elif plan == "premium":
            return self.premium_cost
        elif plan == "pay-as-you-go":
            return usage_gb * self.pay_as_you_go_rate
        else:
            raise ValueError("Invalid billing plan.")