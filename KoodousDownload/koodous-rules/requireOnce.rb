$loadedDep = {}

def requireOnce(dep)
	if $loadedDep[dep].nil?
		$loadedDep[dep] = true
		require dep
	end
end
