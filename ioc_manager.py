from lumudblib.main import main
from lumudblib.utils import check_process

if __name__ == "__main__":
    check_process(__file__, kill_in=0)
    main()
