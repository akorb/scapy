import unittest
from typing import List

from scapy.tools.packet_viewer.datalayer.funcs import (
    variance,
    pairwise,
    data_flips,
    bit_flips,
    average,
    pearson_corr_coeff,
    bit_flips_for_correlation,
    bit_flip_correlation,
)


class FuncsTest(unittest.TestCase):
    @staticmethod
    def test_variance():
        # 1, 2, 7, 15, 25, 36
        pks = [15, 7, 2, 25, 1, 36]
        res = variance(pks)
        assert res == 13.2

    @staticmethod
    def test_pairwise():
        values = [1, 2, 3, 4]
        iterator = pairwise(values)

        iterator_a, iterator_b = iterator.__next__()
        assert iterator_a == 1
        assert iterator_b == 2

        iterator_a, iterator_b = iterator.__next__()
        assert iterator_a == 2
        assert iterator_b == 3

        iterator_a, iterator_b = iterator.__next__()
        assert iterator_a == 3
        assert iterator_b == 4

        try:
            iterator.__next__()
            assert False
        except StopIteration:
            assert True

    def test_data_flips(self):
        data = ["0000000000000000", "1000000000000000", "1010000000000000"]
        expected_result = [1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        result = data_flips(data, 16)

        self.assertEqual(expected_result, result)

    def test_bit_flips(self):
        data = [b"\x05\x89\x89\x89", b"\x06\x89\x89\x89", b"\x55\x89\x89\x00"]

        expected_result = [
            0,
            1,
            0,
            1,
            0,
            0,
            2,
            2,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            1,
        ]
        result = bit_flips(data)

        self.assertEqual(expected_result, result)

    def test_average(self):
        values = [2, 5, 9, 3, 30, 0.5]
        avg = average(values)
        self.assertEqual(avg, 8.25)

        values = [0, 0, 0, 0, 0, 0]
        avg = average(values)

        self.assertEqual(avg, 0)

        values = []
        avg = average(values)
        self.assertEqual(avg, 0)

    def test_pearson_corr_coeff(self):
        values_x: List[float] = []
        values_y: List[float] = []
        corr_coeff = pearson_corr_coeff(values_x, values_y)
        self.assertIsNone(corr_coeff)

        values_x.append(0.0)
        values_y.extend([1.0, 3.5])
        corr_coeff = pearson_corr_coeff(values_x, values_y)
        self.assertIsNone(corr_coeff)

        values_x.append(0.0)
        corr_coeff = pearson_corr_coeff(values_x, values_y)
        self.assertIsNone(corr_coeff)

        values_x.extend([15, 4.3, 2])
        values_y.extend([0, 2, 4])
        corr_coeff = pearson_corr_coeff(values_x, values_y)
        self.assertEqual(corr_coeff, -0.6713580109407455)

        values_y = [1, 2, 3, 4, 5, 6]
        values_x = [1, 2, 3, 4, 5, 6]
        corr_coeff = pearson_corr_coeff(values_x, values_y)
        self.assertEqual(corr_coeff, 1)

        values_x = [6, 5, 4, 3, 2, 1]
        corr_coeff = pearson_corr_coeff(values_x, values_y)
        self.assertEqual(corr_coeff, -1)

    def test_bit_flips_for_correlation(self):
        all_data_in_bits = ["0000", "1000", "1100", "0101", "0111", "1111"]

        all_bit_flips = bit_flips_for_correlation(all_data_in_bits, 4, 6)

        expected_result = [[1, 0, 1, 0, 1], [0, 1, 0, 0, 0], [0, 0, 0, 1, 0], [0, 0, 1, 0, 0]]

        self.assertEqual(all_bit_flips, expected_result)

    def test_bit_flip_correlation_none(self):
        all_data = [b"\x05", b"\x04", b"\x01", b"\x01"]
        result = bit_flip_correlation(all_data)

        self.assertEqual(result, [None, None, None, None, None, None, None])

    def test_bit_flip_correlation(self):
        all_data = [b"\x05", b"\x04", b"\x03", b"\x01"]
        result = bit_flip_correlation(all_data)

        self.assertEqual(result, [None, None, None, None, None, 0.5, -0.5])
