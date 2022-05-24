// PERMUTE_ARGS:
// Generate \sum_{i=0}^{14} 2^i = 32767 template instantiations
// (each with 3 sections) to use more than 64Ki sections in total.
version (Win32)
{
    // Apparently omf or optlink does not support more than 32767 symbols.
    void main()
    {
    }
}
else
{
    size_t foo(size_t i, size_t mask)()
    {
        static if (i == 14)
            return mask;
        else
            return foo!(i + 1, mask) + foo!(i + 1, mask | (1UL << i));
    }

    void main()
    {
        assert(foo!(0, 0) != 0);
    }
}
